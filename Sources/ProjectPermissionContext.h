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

#include "OrthancDatabase.h"
#include "Models/DocumentOrientedDatabase.h"
#include "Models/Project.h"
#include "Permissions/AuthenticatedUser.h"
#include "Permissions/IPermissionContext.h"

class ProjectPermissionContext : public IPermissionContext
{
public:
  static DocumentOrientedDatabase& GetProjects();  // This class is thread-safe

  static ProjectAccessMode GetProjectAccessMode(const AuthenticatedUser& user,
                                                const std::string& projectId,
                                                const Project& project);

  virtual void LookupRolesOfUser(std::set<std::string>& projectsAsInstructor,
                                 std::set<std::string>& projectsAsLearner,
                                 const std::string& userId) const ORTHANC_OVERRIDE;

  virtual bool LookupProjectFromLtiContext(std::string& projectId /* out */,
                                           int64_t ltiContextId /* in */) const ORTHANC_OVERRIDE;

  class Factory : public IFactory
  {
  public:
    virtual IPermissionContext* CreateContext() const ORTHANC_OVERRIDE
    {
      return new ProjectPermissionContext;
    }
  };

  class Granter : public OrthancDatabase::IProjectGranter
  {
  private:
    const AuthenticatedUser&  user_;

  public:
    Granter(const AuthenticatedUser& user) :
      user_(user)
    {
    }

    virtual bool HasAccessToSomeProject(const std::set<std::string>& projectIds) const ORTHANC_OVERRIDE;
  };
};
