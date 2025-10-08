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


#include "PlatformKeysRegistry.h"

#include "SecurityConstants.h"

#include <OrthancPluginCppWrapper.h>
#include <SerializationToolbox.h>

#include <cassert>


void PlatformKeysRegistry::ClearUnsafe()
{
  for (Keys::iterator it = keys_.begin(); it != keys_.end(); ++it)
  {
    assert(it->second != NULL);
    delete it->second;
  }

  keys_.clear();
  isLoaded_ = false;
}


bool PlatformKeysRegistry::LookupKey(RSAPublicKey& target,
                                     const std::string& keyId)
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);

  if (!isLoaded_)
  {
    return false;
  }
  else
  {
    Keys::const_iterator found = keys_.find(keyId);
    if (found == keys_.end())
    {
      return false;
    }
    else
    {
      assert(found->second != NULL);
      target.Import_JWKS_RS256(*found->second);
      return true;
    }
  }
}


void PlatformKeysRegistry::Update(const std::string& url,
                                  unsigned int maxAge /* in seconds */)
{
  {
    boost::shared_lock<boost::shared_mutex> lock(mutex_);

    int now = time(NULL);

    if (isLoaded_ &&
        (url == lastUrl_) &&
        (now - lastUpdate_) < maxAge)
    {
      // No update is needed
      return;
    }
  }

  LoadKeys(url);
}


PlatformKeysRegistry::PlatformKeysRegistry() :
  isLoaded_(false)
{
}


void PlatformKeysRegistry::LoadKeys(const std::string& url)
{
  Json::Value jwks;

  try
  {
    OrthancPlugins::HttpClient client;
    client.SetTimeout(5);  // 5 seconds to avoid freezing
    client.SetUrl(url);
    OrthancPlugins::HttpHeaders headers;
    client.Execute(headers, jwks);
  }
  catch (Orthanc::OrthancException& e)
  {
    LOG(WARNING) << "Cannot load the JWKS from: " << url;
    return;
  }

  if (!jwks.isMember(JWKS_FIELD_KEYS) ||
      jwks[JWKS_FIELD_KEYS].type() != Json::arrayValue)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol);
  }

  const Json::Value& keys = jwks[JWKS_FIELD_KEYS];

  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);

    ClearUnsafe();

    for (Json::Value::ArrayIndex i = 0; i < keys.size(); i++)
    {
      const Json::Value& key = jwks[JWKS_FIELD_KEYS][i];
      std::string keyId = Orthanc::SerializationToolbox::ReadString(key, JWKS_FIELD_KID);

      if (keys_.find(keyId) == keys_.end())  // Don't load twice the same key
      {
        keys_[keyId] = new Json::Value(key);
      }
    }

    lastUrl_ = url;
    lastUpdate_ = time(NULL);
    isLoaded_ = true;
  }
}

void PlatformKeysRegistry::VerifyJWT(const JWT& jwt,
                                     const std::string& url,
                                     unsigned int maxPlatformKeysAge /* seconds */)
{
  Update(url, maxPlatformKeysAge);

  RSAPublicKey key;

  if (LookupKey(key, jwt.GetKeyId()))
  {
    if (!jwt.Verify(key))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol, "Cannot verify the JWT");
    }
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol, "Unknown platform key ID: " + jwt.GetKeyId());
  }
}
