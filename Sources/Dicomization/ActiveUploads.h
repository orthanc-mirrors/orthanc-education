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


#pragma once

#include <TemporaryFile.h>

#include <boost/thread/mutex.hpp>


class ActiveUploads : public boost::noncopyable
{
private:
  class Upload;

  typedef std::map<std::string, Upload*>  Content;

  boost::mutex   mutex_;
  Content        content_;

  void EraseInternal(const std::string& uploadId);

  static void ClearInternal(Content content);

public:
  static ActiveUploads& GetInstance();

  ~ActiveUploads()
  {
    ClearInternal(content_);
  }

  void Clear();

  void Erase(const std::string& uploadId);

  void AppendChunk(const std::string& uploadId,
                   uint64_t start,
                   uint64_t end,
                   uint64_t fileSize,
                   const void* chunk,
                   size_t chunkSize);

  Orthanc::TemporaryFile* ReleaseTemporaryFile(const std::string& uploadId);

  void RemoveExpired(unsigned int maxSeconds);
};
