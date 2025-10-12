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

#include "../HttpToolbox.h"
#include "../Security/JWT.h"
#include "../Security/RSAPublicKey.h"
#include "../Security/RSAPrivateKey.h"

#include <orthanc/OrthancCPlugin.h>
#include <Cache/LeastRecentlyUsedIndex.h>


class LTIContext : public boost::noncopyable
{
private:
  class Session;

  typedef Orthanc::LeastRecentlyUsedIndex<std::string, Session*>  Sessions;

  boost::mutex   mutex_;
  RSAPrivateKey  privateKey_;
  RSAPublicKey   publicKey_;
  std::string    keyId_;
  Sessions       sessions_;

  bool LookupSessionUnsafe(std::string& sessionId,
                           std::string& state,
                           std::string& nonce,
                           const std::list<HttpToolbox::Cookie>& cookies);

  void OpenSessionUnsafe(std::string& sessionId,
                         std::string& state,
                         std::string& nonce);

public:
  ~LTIContext();

  void CreatePrivateKey();

  void LoadPrivateKey(const std::string& keyId,
                      const std::string& pem);

  void ForgeJWT(std::string& jwt,
                const Json::Value& payload,
                unsigned int maxAge /* in seconds */);

  bool VerifyJWT(const JWT& jwt);

  void EnterSession(OrthancPluginRestOutput* output,
                    std::string& state,
                    std::string& nonce,
                    const std::string& cookieHeader,
                    bool secureCookie);

  void CloseSession(OrthancPluginRestOutput* output,
                    bool secureCookie);

  bool CheckSession(const std::string& cookieHeader,
                    const std::string& state);

  class Lock : public boost::noncopyable
  {
  private:
    boost::mutex::scoped_lock  lock_;
    LTIContext&                context_;

  public:
    explicit Lock(LTIContext& context) :
      lock_(context.mutex_),
      context_(context)
    {
    }

    RSAPrivateKey& GetPrivateKey()
    {
      return context_.privateKey_;
    }

    RSAPublicKey& GetPublicKey()
    {
      return context_.publicKey_;
    }

    const std::string& GetKeyId() const
    {
      return context_.keyId_;
    }
  };
};
