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


#include "JWT.h"

#include "../HttpToolbox.h"
#include "SecurityConstants.h"

#include <SerializationToolbox.h>
#include <Toolbox.h>

#include <boost/math/special_functions/round.hpp>


JWT::JWT(const std::string& jwt)
{
  std::vector<std::string> tokens;
  Orthanc::Toolbox::TokenizeString(tokens, jwt, '.');

  if (tokens.size() != 3)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
  }

  message_ = tokens[0] + "." + tokens[1];

  std::string headerString;
  HttpToolbox::DecodeBase64Url(headerString, tokens[0]);

  Json::Value header;
  if (!Orthanc::Toolbox::ReadJson(header, headerString) ||
      Orthanc::SerializationToolbox::ReadString(header, JWKS_FIELD_TYP) != "JWT")
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
  }

  if (Orthanc::SerializationToolbox::ReadString(header, JWKS_FIELD_ALG) != "RS256")
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
  }

  keyId_ = Orthanc::SerializationToolbox::ReadString(header, JWKS_FIELD_KID, "");

  std::string payloadString;
  HttpToolbox::DecodeBase64Url(payloadString, tokens[1]);

  if (!Orthanc::Toolbox::ReadJson(payload_, payloadString))
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
  }

  HttpToolbox::DecodeBase64Url(signature_, tokens[2]);
}


bool JWT::Verify(RSAPublicKey& key) const
{
  if (key.VerifyRS256(signature_, message_))
  {
    static const char* const FIELD_EXP = "exp";

    if (payload_.isMember(FIELD_EXP))
    {
      // The "exp" field can be either an integer or decimal, so we
      // deal with the worst case of a double
      const double doubleExp = payload_[FIELD_EXP].asDouble();
      const int64_t exp = static_cast<int64_t>(boost::math::llround(doubleExp));
      const int64_t now = time(NULL);
      return now < exp;
    }
    else
    {
      return true;  // No expiration date in the JWT
    }
  }
  else
  {
    return false;
  }
}
