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

#include "PointerRAII.h"

#include <openssl/evp.h>
#include <json/value.h>


class RSAPrivateKey : public boost::noncopyable
{
  friend class RSAPublicKey;

private:
  PointerRAII<EVP_PKEY>   key_;

public:
  RSAPrivateKey() :
    key_(EVP_PKEY_free)
  {
  }

  bool IsValid()
  {
    return key_.GetValue() != NULL;
  }

  void Generate(unsigned int bits = 2048);

  void SerializePrivate(std::string& pem);

  void SerializePublic(std::string& pem);

  void Unserialize(const std::string& pem);

  void SignRS256(std::string& signature,
                 const std::string& buffer);

  void GetExponent(std::string& exponent);

  void GetModulus(std::string& modulus);

  void Export_JWKS_RS256(Json::Value& target,
                         const std::string& keyId);

  void ForgeJWT(std::string& jwt,
                const std::string& keyId,
                const Json::Value& payload);
};
