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

#include "JWT.h"
#include "RSAPublicKey.h"

#include <boost/thread/shared_mutex.hpp>
#include <stdint.h>

class PlatformKeysRegistry : public boost::noncopyable
{
private:
  typedef std::map<std::string, Json::Value*>  Keys;

  boost::shared_mutex mutex_;
  Keys                keys_;
  bool                isLoaded_;
  std::string         lastUrl_;
  int64_t             lastUpdate_;

  void ClearUnsafe();

  bool LookupKey(RSAPublicKey& target,
                 const std::string& keyId);

  void Update(const std::string& url,
              unsigned int maxAge /* in seconds */);

public:
  PlatformKeysRegistry();

  ~PlatformKeysRegistry()
  {
    ClearUnsafe();
  }

  void LoadKeys(const std::string& url);

  void VerifyJWT(const JWT& jwt,
                 const std::string& url,
                 unsigned int maxPlatformKeysAge /* seconds */);
};
