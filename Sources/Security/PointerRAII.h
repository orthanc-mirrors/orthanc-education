/**
 * SPDX-FileCopyrightText: 2024-2026 Sebastien Jodogne, EPL UCLouvain, Belgium
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Orthanc for Education
 * Copyright (C) 2024-2026 Sebastien Jodogne, EPL UCLouvain, Belgium
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

#include <Logging.h>
#include <OrthancException.h>

#include <boost/noncopyable.hpp>

#include <cassert>

template <typename T>
class PointerRAII : public boost::noncopyable
{
private:
  typedef void (*Free1) (T*);
  typedef int (*Free2) (T*);

  T*    value_;
  Free1 free1_;
  Free2 free2_;
  int   free2SuccessCode_;

public:
  explicit PointerRAII(Free1 free1) :
    value_(NULL),
    free1_(free1),
    free2_(NULL),
    free2SuccessCode_(0)
  {
    if (free1 == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_NullPointer);
    }
  }

  PointerRAII(Free2 free2,
              int free2SuccessCode) :
    value_(NULL),
    free1_(NULL),
    free2_(free2),
    free2SuccessCode_(free2SuccessCode)
  {
    if (free2 == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_NullPointer);
    }
  }

  ~PointerRAII()
  {
    Clear();
  }

  void Clear()
  {
    if (value_ != NULL)
    {
      if (free1_ != NULL)
      {
        assert(free2_ == NULL);
        free1_(value_);
      }
      else if (free2_ != NULL)
      {
        assert(free1_ == NULL);
        int code = free2_(value_);
        if (code != free2SuccessCode_)
        {
          LOG(ERROR) << "Error code while freeing a C pointer: " << code;
        }
      }
      else
      {
        assert(0);
      }

      value_ = NULL;
    }
  }

  void Assign(T* value)
  {
    Clear();

    if (value == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_NullPointer);
    }
    else
    {
      value_ = value;
    }
  }

  T*& GetValue()
  {
    return value_;
  }
};
