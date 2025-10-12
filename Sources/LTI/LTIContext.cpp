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


#include "LTIContext.h"

#include "../EducationEnumerations.h"
#include "../HttpToolbox.h"

#include <cassert>


static const char* const COOKIE_OIDC_SESSION = "orthanc-education-oidc";


class LTIContext::Session : public boost::noncopyable
{
private:
  std::string  state_;
  std::string  nonce_;

public:
  Session() :
    state_(Orthanc::Toolbox::GenerateUuid()),
    nonce_(Orthanc::Toolbox::GenerateUuid())
  {
  }

  const std::string& GetState() const
  {
    return state_;
  }

  const std::string& GetNonce() const
  {
    return nonce_;
  }
};


bool LTIContext::LookupSessionUnsafe(std::string& sessionId,
                                     std::string& state,
                                     std::string& nonce,
                                     const std::list<HttpToolbox::Cookie>& cookies)
{
  // The same cookie might be present multiple times, hence the loop
  for (std::list<HttpToolbox::Cookie>::const_iterator cookie = cookies.begin(); cookie != cookies.end(); ++cookie)
  {
    if (cookie->GetKey() == COOKIE_OIDC_SESSION)
    {
      sessionId = cookie->GetValue();

      Session* session = NULL;
      if (sessions_.Contains(sessionId, session))
      {
        if (session == NULL)
        {
          throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
        }
        else
        {
          state = session->GetState();
          nonce = session->GetNonce();
          sessions_.MakeMostRecent(sessionId);
          return true;
        }
      }
    }
  }

  return false;
}


void LTIContext::OpenSessionUnsafe(std::string& sessionId,
                                   std::string& state,
                                   std::string& nonce)
{
  {
    std::unique_ptr<Session> session(new Session);

    sessionId = Orthanc::Toolbox::GenerateUuid();
    state = session->GetState();
    nonce = session->GetNonce();

    sessions_.Add(sessionId, session.release());
  }

  if (sessions_.GetSize() > 1000 /* maximum number of active sessions */)
  {
    Session* session = NULL;
    std::string s = sessions_.RemoveOldest(session);
    assert(session != NULL);
    delete session;
    LOG(INFO) << "Closing old LTI session: " << s;
  }
}


LTIContext::~LTIContext()
{
  while (!sessions_.IsEmpty())
  {
    Session* session = NULL;
    sessions_.RemoveOldest(session);
    assert(session != NULL);
    delete session;
  }
}


void LTIContext::CreatePrivateKey()
{
  boost::mutex::scoped_lock lock(mutex_);

  LOG(WARNING) << "Generating a private RSA key using OpenSSL";
  keyId_ = Orthanc::Toolbox::GenerateUuid();
  privateKey_.Generate();
  LOG(INFO) << "Generation of the private RSA key is done";

  publicKey_.LoadFromPrivate(privateKey_);
}


void LTIContext::LoadPrivateKey(const std::string& keyId,
                                const std::string& pem)
{
  if (keyId.empty() ||
      pem.empty())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
  else
  {
    keyId_ = keyId;
    privateKey_.Unserialize(pem);
    publicKey_.LoadFromPrivate(privateKey_);
  }
}


void LTIContext::ForgeJWT(std::string& jwt,
                          const Json::Value& payload,
                          unsigned int maxAge /* in seconds */)
{
  if (payload.type() != Json::objectValue)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadParameterType);
  }

  const int64_t now = time(NULL);

  Json::Value enriched = payload;
  enriched["iat"] = static_cast<Json::Value::Int64>(now);
  enriched["exp"] = static_cast<Json::Value::Int64>(now + maxAge);

  {
    boost::mutex::scoped_lock lock(mutex_);
    privateKey_.ForgeJWT(jwt, keyId_, enriched);
  }
}


bool LTIContext::VerifyJWT(const JWT& jwt)
{
  boost::mutex::scoped_lock lock(mutex_);
  return jwt.Verify(publicKey_);
}


void LTIContext::EnterSession(OrthancPluginRestOutput* output,
                              std::string& state,
                              std::string& nonce,
                              const std::string& cookieHeader,
                              bool secureCookie)
{
  std::list<HttpToolbox::Cookie> cookies;
  HttpToolbox::ParseCookies(cookies, cookieHeader);

  {
    boost::mutex::scoped_lock lock(mutex_);

    std::string sessionId;

    if (!LookupSessionUnsafe(sessionId, state, nonce, cookies))
    {
      OpenSessionUnsafe(sessionId, state, nonce);
      HttpToolbox::SetCookie(output, COOKIE_OIDC_SESSION, sessionId, CookieSameSite_None, secureCookie);
      LOG(INFO) << "Opening new LTI session: " << sessionId;
    }
    else
    {
      LOG(INFO) << "Reusing old LTI session: " << sessionId;
    }
  }
}


void LTIContext::CloseSession(OrthancPluginRestOutput* output,
                              bool secureCookie)
{
  HttpToolbox::ClearCookie(output, COOKIE_OIDC_SESSION, CookieSameSite_None, secureCookie);
}


bool LTIContext::CheckSession(const std::string& cookieHeader,
                              const std::string& expectedState)
{
  std::list<HttpToolbox::Cookie> cookies;
  HttpToolbox::ParseCookies(cookies, cookieHeader);

  {
    boost::mutex::scoped_lock lock(mutex_);

    std::string sessionId, state, nonce;
    return (LookupSessionUnsafe(sessionId, state, nonce, cookies) &&
            state == expectedState);
  }
}
