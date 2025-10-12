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


#include "DocumentOrientedDatabase.h"

#include <Logging.h>
#include <OrthancException.h>
#include <OrthancPluginCppWrapper.h>
#include <SerializationToolbox.h>
#include <Toolbox.h>

#include <cassert>


void DocumentOrientedDatabase::Clear()
{
  for (Documents::iterator it = documents_.begin(); it != documents_.end(); ++it)
  {
    assert(it->second != NULL);
    delete it->second;
  }

  documents_.clear();
}


void DocumentOrientedDatabase::UpdateLargestIntegerKey(const std::string& key)
{
  uint64_t keyAsInteger;

  if (Orthanc::SerializationToolbox::ParseUnsignedInteger64(keyAsInteger, key))
  {
    largestIntegerKey_ = std::max(largestIntegerKey_, keyAsInteger);
  }
}


void DocumentOrientedDatabase::StoreInternal(const std::string& key,
                                             ISerializableDocument* value,
                                             const std::string& serialized)
{
  // Mutex be locked in writer mode

  assert(value != NULL);
  std::unique_ptr<ISerializableDocument> protection(value);

  Documents::iterator found = documents_.find(key);
  if (found == documents_.end())
  {
    documents_[key] = protection.release();
  }
  else
  {
    assert(found->second != NULL);
    delete found->second;
    found->second = protection.release();
  }

  UpdateLargestIntegerKey(key);

  {
    // Only modify the Orthanc database once we're sure the memory has been properly updated
    OrthancPlugins::KeyValueStore store(storeId_);
    store.Store(key, serialized);
  }
}


DocumentOrientedDatabase::DocumentOrientedDatabase(const std::string& storeId,
                                                   IDocumentUnserializer* unserializer /* takes ownership */) :
  storeId_(storeId),
  unserializer_(unserializer),
  largestIntegerKey_(0)
{
  if (unserializer == NULL)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NullPointer);
  }
}


void DocumentOrientedDatabase::Load()
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);

  Clear();

  OrthancPlugins::KeyValueStore store(storeId_);

  std::unique_ptr<OrthancPlugins::KeyValueStore::Iterator> iterator(store.CreateIterator());

  while (iterator->Next())
  {
    if (documents_.find(iterator->GetKey()) != documents_.end())
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }

    UpdateLargestIntegerKey(iterator->GetKey());

    std::string serialized;
    iterator->GetValue(serialized);

    bool ok = false;

    Json::Value json;
    if (Orthanc::Toolbox::ReadJson(json, serialized))
    {
      try
      {
        documents_[iterator->GetKey()] = unserializer_->Unserialize(json);
        ok = true;
      }
      catch (Orthanc::OrthancException& e)
      {
      }
    }

    if (!ok)
    {
      LOG(WARNING) << "Cannot unserialize document \"" << iterator->GetKey() << "\" from key-value store \"" << storeId_ << "\"";
    }
  }
}


void DocumentOrientedDatabase::Store(const std::string& key,
                                     ISerializableDocument* document /* takes ownership */)
{
  std::unique_ptr<ISerializableDocument> protection(document);

  if (document == NULL)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NullPointer);
  }

  Json::Value serialized;
  protection->Serialize(serialized);

  std::string value;
  Orthanc::Toolbox::WriteFastJson(value, serialized);

  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    StoreInternal(key, protection.release(), value);
  }
}


std::string DocumentOrientedDatabase::StoreWithAutoincrementedKey(ISerializableDocument* document /* takes ownership */)
{
  std::unique_ptr<ISerializableDocument> protection(document);

  if (document == NULL)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NullPointer);
  }

  Json::Value serialized;
  protection->Serialize(serialized);

  std::string value;
  Orthanc::Toolbox::WriteFastJson(value, serialized);

  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);

    const std::string key = boost::lexical_cast<std::string>(largestIntegerKey_ + 1);

    StoreInternal(key, protection.release(), value);

    return key;
  }
}


void DocumentOrientedDatabase::Remove(const std::string& key)
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);

  Documents::iterator found = documents_.find(key);
  if (found != documents_.end())
  {
    assert(found->second != NULL);
    delete found->second;
    documents_.erase(key);
  }

  {
    // Only modify the Orthanc database once we're sure the memory has been properly updated
    OrthancPlugins::KeyValueStore store(storeId_);
    store.DeleteKey(key);
  }
}


DocumentOrientedDatabase::Iterator::Iterator(DocumentOrientedDatabase& database) :
  lock_(database.mutex_),
  first_(true),
  current_(database.documents_.begin()),
  end_(database.documents_.end())
{
}


bool DocumentOrientedDatabase::Iterator::Next()
{
  if (first_)
  {
    first_ = false;
    return (current_ != end_);
  }
  else if (current_ == end_)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }
  else
  {
    ++current_;
    return (current_ != end_);
  }
}


const std::string& DocumentOrientedDatabase::Iterator::GetKey() const
{
  if (first_ ||
      current_ == end_)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }
  else
  {
    return current_->first;
  }
}


const ISerializableDocument& DocumentOrientedDatabase::Iterator::GetDocument() const
{
  if (first_ ||
      current_ == end_)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }
  else
  {
    assert(current_->second != NULL);
    return *current_->second;
  }
}


DocumentOrientedDatabase::Reader::Reader(DocumentOrientedDatabase& database) :
  lock_(database.mutex_),
  database_(database)
{
}


const ISerializableDocument& DocumentOrientedDatabase::Reader::GetDocument(const std::string& key) const
{
  Documents::const_iterator found = database_.documents_.find(key);
  if (found == database_.documents_.end())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
  }
  else
  {
    assert(found->second != NULL);
    return *found->second;
  }
}


const ISerializableDocument* DocumentOrientedDatabase::Reader::LookupDocument(const std::string& key) const
{
  Documents::const_iterator found = database_.documents_.find(key);
  if (found == database_.documents_.end())
  {
    return NULL;
  }
  else
  {
    assert(found->second != NULL);
    return found->second;
  }
}


ISerializableDocument* DocumentOrientedDatabase::CloneDocument(const std::string& key)
{
  Reader reader(*this);

  const ISerializableDocument* document = reader.LookupDocument(key);

  if (document == NULL)
  {
    return NULL;
  }
  else
  {
    assert(document != NULL);
    return document->Clone();
  }
}
