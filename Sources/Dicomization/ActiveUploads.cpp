/**
 * SPDX-FileCopyrightText: 2024-2025 Sebastien Jodogne, ICTEAM UCLouvain, Belgium
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Orthanc for Education
 * Copyright (C) 2024-2025 Sebastien Jodogne, EPL UCLouvain, Belgium
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 **/


#include "ActiveUploads.h"

#include <OrthancException.h>

#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/stream.hpp>
#include <fstream>


static boost::posix_time::ptime GetNow()
{
  return boost::posix_time::second_clock::local_time();
}


class ActiveUploads::Upload : public boost::noncopyable
{
private:
  std::unique_ptr<Orthanc::TemporaryFile>  file_;
  uint64_t                                 pos_;
  uint64_t                                 fileSize_;
  boost::posix_time::ptime                 lastUpdate_;

public:
  Upload(uint64_t fileSize) :
    file_(new Orthanc::TemporaryFile),
    pos_(0),
    fileSize_(fileSize),
    lastUpdate_(GetNow())
  {
  }

  Orthanc::TemporaryFile* ReleaseTemporaryFile()
  {
    if (pos_ == fileSize_)
    {
      return file_.release();
    }
    else
    {
      return NULL;
    }
  }

  bool AppendChunk(uint64_t start,
                   uint64_t fileSize,
                   const void* data,
                   size_t size)
  {
    if (fileSize != fileSize_)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
    }

    if (file_.get() == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
    }

    if (pos_ != start ||
        pos_ + size > fileSize_)
    {
      return false;
    }
    else if (size == 0)
    {
      return true;
    }
    else
    {
      try
      {
        boost::iostreams::stream<boost::iostreams::file_descriptor_sink> f;

        f.open(file_->GetPath(), std::ofstream::out | std::ofstream::binary | std::ofstream::app);
        if (!f.good())
        {
          return false;
        }

        f.write(reinterpret_cast<const char*>(data), size);

        bool good = f.good();
        f.close();

        if (good)
        {
          pos_ += static_cast<uint64_t>(size);
          lastUpdate_ = GetNow();
          return true;
        }
        else
        {
          return false;
        }
      }
      catch (boost::filesystem::filesystem_error&)
      {
      }
      catch (...)  // To catch "std::system_error&" in C++11
      {
      }

      return false;
    }
  }

  bool HasExpired(unsigned int maxAgeSeconds) const
  {
    return (GetNow() - lastUpdate_).total_seconds() > maxAgeSeconds;
  }
};


void ActiveUploads::EraseInternal(const std::string& uploadId)
{
  // Mutex must be locked
  Content::iterator found = content_.find(uploadId);
  if (found != content_.end())
  {
    assert(found != content_.end());
    assert(found->second != NULL);
    delete found->second;
    content_.erase(uploadId);
  }
}


void ActiveUploads::ClearInternal(Content content)
{
  // Mutex must be locked
  for (Content::iterator it = content.begin(); it != content.end(); ++it)
  {
    if (it->second != NULL)
    {
      delete it->second;
    }
  }

  content.clear();
}


ActiveUploads& ActiveUploads::GetInstance()
{
  static ActiveUploads instance;
  return instance;
}


void ActiveUploads::Clear()
{
  boost::mutex::scoped_lock lock(mutex_);
  ClearInternal(content_);
}


void ActiveUploads::Erase(const std::string& uploadId)
{
  boost::mutex::scoped_lock lock(mutex_);
  EraseInternal(uploadId);
}


void ActiveUploads::AppendChunk(const std::string& uploadId,
                                uint64_t start,
                                uint64_t end,
                                uint64_t fileSize,
                                const void* chunk,
                                size_t chunkSize)
{
  boost::mutex::scoped_lock lock(mutex_);

  try
  {
    if (start > end ||
        end >= fileSize ||
        end - start + 1 != chunkSize)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol, "Bad range header");
    }

    Content::iterator found = content_.find(uploadId);
    if (found == content_.end())
    {
      std::unique_ptr<Upload> upload(new Upload(fileSize));

      if (!upload->AppendChunk(start, fileSize, chunk, chunkSize))
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol, "Mismatch in uploaded chunk");
      }

      content_[uploadId] = upload.release();
    }
    else
    {
      assert(found->second != NULL);

      if (!found->second->AppendChunk(start, fileSize, chunk, chunkSize))
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol, "Mismatch in uploaded chunk");
      }
    }
  }
  catch (Orthanc::OrthancException&)
  {
    EraseInternal(uploadId);
    throw;
  }
}


Orthanc::TemporaryFile* ActiveUploads::ReleaseTemporaryFile(const std::string& uploadId)
{
  boost::mutex::scoped_lock lock(mutex_);

  Content::iterator found = content_.find(uploadId);
  if (found == content_.end())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
  }
  else
  {
    assert(found->second != NULL);

    std::unique_ptr<Orthanc::TemporaryFile> file(found->second->ReleaseTemporaryFile());

    EraseInternal(uploadId);

    if (file.get() == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls, "Cannot release an incomplete upload");
    }
    else
    {
      return file.release();
    }
  }
}


void ActiveUploads::RemoveExpired(unsigned int maxSeconds)
{
  boost::mutex::scoped_lock lock(mutex_);

  Content newContent;

  try
  {
    for (Content::iterator it = content_.begin(); it != content_.end(); ++it)
    {
      assert(it->second != NULL);
      if (it->second->HasExpired(maxSeconds))
      {
        delete it->second;
      }
      else
      {
        newContent[it->first] = it->second;
        it->second = NULL;
      }
    }
  }
  catch (Orthanc::OrthancException&)
  {
    ClearInternal(newContent);
    throw;
  }

  content_ = newContent;
}
