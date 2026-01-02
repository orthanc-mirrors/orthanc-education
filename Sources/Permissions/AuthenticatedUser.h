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

#include "IPermissionContext.h"
#include "../EducationEnumerations.h"
#include "../LTI/LTIContext.h"

#include <OrthancPluginCppWrapper.h>

#include <stdint.h>


class AuthenticatedUser : public boost::noncopyable
{
private:
  Role                   role_;
  bool                   hasUserId_;
  std::string            userId_;
  std::set<std::string>  projectsAsInstructor_;
  std::set<std::string>  projectsAsLearner_;
  bool                   hasLtiProjectId_;
  std::string            ltiProjectId_;

  explicit AuthenticatedUser(Role role);

  static AuthenticatedUser* Unserialize(const Json::Value& payload);

public:
  void Serialize(Json::Value& payload) const;

  Role GetRole() const
  {
    return role_;
  }

  void SetUserId(const std::string& id);

  bool HasUserId() const
  {
    return hasUserId_;
  }

  const std::string& GetUserId() const;

  void AddInstructorOfProject(const std::string& projectId)
  {
    projectsAsInstructor_.insert(projectId);
  }

  bool IsInstructorOfProject(const std::string& projectId) const
  {
    return projectsAsInstructor_.find(projectId) != projectsAsInstructor_.end();
  }

  const std::set<std::string> GetProjectsAsInstructor() const
  {
    return projectsAsInstructor_;
  }

  void AddLearnerOfProject(const std::string& projectId)
  {
    projectsAsLearner_.insert(projectId);
  }

  bool IsLearnerOfProject(const std::string& projectId) const
  {
    return projectsAsLearner_.find(projectId) != projectsAsLearner_.end();
  }

  const std::set<std::string> GetProjectsAsLearner() const
  {
    return projectsAsLearner_;
  }

  void SetLtiProjectId(const std::string& projectId);

  bool HasLtiProjectId() const
  {
    return hasLtiProjectId_;
  }

  const std::string& GetLtiProjectId() const;

  std::string Format() const;

  void ToHttpRequest(OrthancPlugins::MemoryBuffer& payload) const;

  void ForgeJWT(std::string& jwt,
                LTIContext& context,
                unsigned int maxAge /* in seconds */) const;

  static AuthenticatedUser* FromLti(const IPermissionContext& context,
                                    const Json::Value& payload);

  static AuthenticatedUser* FromHttpRequest(const OrthancPluginHttpRequest* request);

  static AuthenticatedUser* FromJWT(LTIContext& context,
                                    const std::string& jwt);

  static AuthenticatedUser* CreateAdministrator(const std::string& userId);

  static AuthenticatedUser* CreateStandardUser(const IPermissionContext& context,
                                               const std::string& userId);

  static AuthenticatedUser* CreateGuest()
  {
    return new AuthenticatedUser(Role_Guest);
  }
};
