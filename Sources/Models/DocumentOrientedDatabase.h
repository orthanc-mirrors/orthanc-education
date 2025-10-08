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

#include "IDocumentUnserializer.h"

#include <Compatibility.h>  // For std::unique_ptr<>

#include <boost/thread/shared_mutex.hpp>
#include <boost/thread/lock_types.hpp>

class DocumentOrientedDatabase : public boost::noncopyable
{
private:
  typedef std::map<std::string, ISerializableDocument*>  Documents;

  boost::shared_mutex                     mutex_;
  std::string                             storeId_;
  std::unique_ptr<IDocumentUnserializer>  unserializer_;
  Documents                               documents_;
  uint64_t                                largestIntegerKey_;

  void Clear();

  void UpdateLargestIntegerKey(const std::string& key);

  void StoreInternal(const std::string& key,
                     ISerializableDocument* value,
                     const std::string& serialized);

public:
  DocumentOrientedDatabase(const std::string& storeId,
                           IDocumentUnserializer* unserializer /* takes ownership */);

  ~DocumentOrientedDatabase()
  {
    Clear();
  }

  void Load();

  void Store(const std::string& key,
             ISerializableDocument* document /* takes ownership */);

  std::string StoreWithAutoincrementedKey(ISerializableDocument* document /* takes ownership */);

  void Remove(const std::string& key);

  class Iterator : public boost::noncopyable
  {
  private:
    boost::shared_lock<boost::shared_mutex>  lock_;
    bool                                     first_;
    Documents::const_iterator                current_;
    Documents::const_iterator                end_;

  public:
    explicit Iterator(DocumentOrientedDatabase& database);

    bool Next();

    const std::string& GetKey() const;

    const ISerializableDocument& GetDocument() const;

    template <typename T>
    const T& GetDocument() const
    {
      return dynamic_cast<const T&>(GetDocument());
    }
  };


  class Reader : public boost::noncopyable
  {
  private:
    boost::shared_lock<boost::shared_mutex>  lock_;
    const DocumentOrientedDatabase&          database_;

  public:
    explicit Reader(DocumentOrientedDatabase& database);

    const ISerializableDocument& GetDocument(const std::string& key) const;

    const ISerializableDocument* LookupDocument(const std::string& key) const;

    template<typename T>
    const T& GetDocument(const std::string& key) const
    {
      return dynamic_cast<const T&>(GetDocument(key));
    }

    template<typename T>
    const T* LookupDocument(const std::string& key) const
    {
      return dynamic_cast<const T*>(LookupDocument(key));
    }
  };


  ISerializableDocument* CloneDocument(const std::string& key);

  template <typename T>
  T* CloneDocument(const std::string& key)
  {
    return dynamic_cast<T*>(CloneDocument(key));
  }
};
