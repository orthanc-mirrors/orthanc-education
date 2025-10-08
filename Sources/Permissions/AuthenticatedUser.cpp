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


#include "AuthenticatedUser.h"

#include "../HttpToolbox.h"

#include <SerializationToolbox.h>


static const char* const FIELD_ROLE = "role";
static const char* const FIELD_INSTRUCTOR = "instructor-of";
static const char* const FIELD_LEARNER = "learner-of";
static const char* const FIELD_ID = "id";
static const char* const FIELD_LTI_PROJECT_ID = "lti-project-id";


void AuthenticatedUser::Serialize(Json::Value& payload) const
{
  payload = Json::objectValue;
  payload[FIELD_ROLE] = EnumerationToString(role_);

  if (hasUserId_)
  {
    payload[FIELD_ID] = userId_;
  }

  Orthanc::SerializationToolbox::WriteSetOfStrings(payload, projectsAsInstructor_, FIELD_INSTRUCTOR);
  Orthanc::SerializationToolbox::WriteSetOfStrings(payload, projectsAsLearner_, FIELD_LEARNER);

  if (hasLtiProjectId_)
  {
    payload[FIELD_LTI_PROJECT_ID] = boost::lexical_cast<std::string>(ltiProjectId_);
  }
}


AuthenticatedUser* AuthenticatedUser::Unserialize(const Json::Value& payload)
{
  Role role = ParseRole(Orthanc::SerializationToolbox::ReadString(payload, FIELD_ROLE));

  std::unique_ptr<AuthenticatedUser> user(new AuthenticatedUser(role));

  if (payload.isMember(FIELD_ID))
  {
    user->SetUserId(Orthanc::SerializationToolbox::ReadString(payload, FIELD_ID));
  }

  Orthanc::SerializationToolbox::ReadSetOfStrings(user->projectsAsInstructor_, payload, FIELD_INSTRUCTOR);
  Orthanc::SerializationToolbox::ReadSetOfStrings(user->projectsAsLearner_, payload, FIELD_LEARNER);

  if (payload.isMember(FIELD_LTI_PROJECT_ID))
  {
    user->SetLtiProjectId(Orthanc::SerializationToolbox::ReadString(payload, FIELD_LTI_PROJECT_ID));
  }

  return user.release();
}


AuthenticatedUser::AuthenticatedUser(Role role) :
  role_(role),
  hasUserId_(false),
  hasLtiProjectId_(false)
{
}


void AuthenticatedUser::SetUserId(const std::string& id)
{
  hasUserId_ = true;
  userId_ = id;
}


const std::string& AuthenticatedUser::GetUserId() const
{
  if (hasUserId_)
  {
    return userId_;
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }
}

void AuthenticatedUser::SetLtiProjectId(const std::string& projectId)
{
  if (projectId.empty())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
  else
  {
    hasLtiProjectId_ = true;
    ltiProjectId_ = projectId;
  }
}


const std::string& AuthenticatedUser::GetLtiProjectId() const
{
  if (hasLtiProjectId_)
  {
    return ltiProjectId_;
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }
}


std::string AuthenticatedUser::Format() const
{
  std::string s = std::string(hasUserId_ ? userId_ : "?") + " with role " + EnumerationToString(role_);

  if (hasLtiProjectId_)
  {
    s += " in LTI project " + boost::lexical_cast<std::string>(ltiProjectId_);
  }

  return s;
}


void AuthenticatedUser::ToHttpRequest(OrthancPlugins::MemoryBuffer& payload) const
{
  Json::Value json;
  Serialize(json);

  payload.AssignJson(json);
}


void AuthenticatedUser::ForgeJWT(std::string& jwt,
                                 LTIContext& context,
                                 unsigned int maxAge /* in seconds */) const
{
  Json::Value payload;
  Serialize(payload);

  context.ForgeJWT(jwt, payload, maxAge);
}


AuthenticatedUser* AuthenticatedUser::FromLti(const IPermissionContext& context,
                                              const Json::Value& payload)
{
  Json::Value ltiContext;
  int64_t contextId;
  if (!HttpToolbox::LookupJsonObject(ltiContext, payload, "https://purl.imsglobal.org/spec/lti/claim/context") ||
      !Orthanc::SerializationToolbox::ParseInteger64(contextId, Orthanc::SerializationToolbox::ReadString(ltiContext, "id")))
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol, "Missing LTI context ID");
  }

  std::string projectId;
  if (!context.LookupProjectFromLtiContext(projectId, contextId))
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol, "Unknown LTI context ID: " +
                                    boost::lexical_cast<std::string>(contextId));
  }

  std::unique_ptr<AuthenticatedUser> user(new AuthenticatedUser(Role_Standard));
  user->SetLtiProjectId(projectId);

  std::set<std::string> roles;
  Orthanc::SerializationToolbox::ReadSetOfStrings(roles, payload, "https://purl.imsglobal.org/spec/lti/claim/roles");

  if (roles.find("http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor") != roles.end())
  {
    user->AddInstructorOfProject(projectId);
  }
  else if (roles.find("http://purl.imsglobal.org/vocab/lis/v2/membership#Learner") != roles.end())
  {
    user->AddLearnerOfProject(projectId);
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol, "Unknown user type in LTI");
  }

  const std::string email = Orthanc::SerializationToolbox::ReadString(payload, "email", "");
  if (!email.empty())
  {
    /**
     * This only happens if option "Share launcher's email with
     * tool" is set to "Always" in the Moodle configuration (in the
     * "Privacy" tab").
     **/
    user->SetUserId(email);
  }

  return user.release();
}


AuthenticatedUser* AuthenticatedUser::FromHttpRequest(const OrthancPluginHttpRequest* request)
{
  Json::Value payload;
  if (Orthanc::Toolbox::ReadJson(payload, request->authenticationPayload, request->authenticationPayloadSize))
  {
    return Unserialize(payload);
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_Unauthorized);
  }
}


AuthenticatedUser* AuthenticatedUser::FromJWT(LTIContext& context,
                                              const std::string& jwt)
{
  JWT parsed(jwt);

  if (context.VerifyJWT(parsed))
  {
    return Unserialize(parsed.GetPayload());
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol);
  }
}


AuthenticatedUser* AuthenticatedUser::CreateAdministrator(const std::string& userId)
{
  std::unique_ptr<AuthenticatedUser> user(new AuthenticatedUser(Role_Administrator));
  user->SetUserId(userId);
  return user.release();
}


AuthenticatedUser* AuthenticatedUser::CreateStandardUser(const IPermissionContext& context,
                                                         const std::string& userId)
{
  std::unique_ptr<AuthenticatedUser> user(new AuthenticatedUser(Role_Standard));
  user->SetUserId(userId);

  context.LookupRolesOfUser(user->projectsAsInstructor_, user->projectsAsLearner_, userId);

  return user.release();
}
