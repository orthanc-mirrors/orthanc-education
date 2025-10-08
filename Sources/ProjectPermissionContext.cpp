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


#include "ProjectPermissionContext.h"

#include "Models/DocumentOrientedDatabase.h"


DocumentOrientedDatabase& ProjectPermissionContext::GetProjects()
{
  static DocumentOrientedDatabase projects("education-projects", new Project::Unserializer);
  return projects;
}


ProjectAccessMode ProjectPermissionContext::GetProjectAccessMode(const AuthenticatedUser& user,
                                                                 const std::string& projectId,
                                                                 const Project& project)
{
  switch (user.GetRole())
  {
  case Role_Administrator:
    return ProjectAccessMode_Writable;

  case Role_Guest:
    if (project.GetPolicy() == ProjectPolicy_Public)
    {
      return ProjectAccessMode_ReadOnly;
    }
    else
    {
      return ProjectAccessMode_None;
    }

  case Role_Standard:
    if (user.IsInstructorOfProject(projectId))
    {
      return ProjectAccessMode_Writable;
    }
    else
    {
      switch (project.GetPolicy())
      {
      case ProjectPolicy_Hidden:
        return ProjectAccessMode_None;

      case ProjectPolicy_Active:
        if (user.IsLearnerOfProject(projectId))
        {
          return ProjectAccessMode_ReadOnly;
        }
        else
        {
          return ProjectAccessMode_None;
        }

      case ProjectPolicy_Public:
        return ProjectAccessMode_ReadOnly;

      default:
        throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
      }
    }

  default:
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }
}


bool ProjectPermissionContext::IsGrantedProject(const AuthenticatedUser& user,
                                                const std::set<std::string>& projectIds) const
{
  DocumentOrientedDatabase::Reader reader(projects_);

  for (std::set<std::string>::const_iterator it = projectIds.begin(); it != projectIds.end(); ++it)
  {
    const Project* project = reader.LookupDocument<Project>(*it);
    if (project != NULL)
    {
      const ProjectAccessMode mode = GetProjectAccessMode(user, *it, *project);
      if (mode == ProjectAccessMode_Writable ||
          mode == ProjectAccessMode_ReadOnly)
      {
        return true;
      }
    }
  }

  return false;
}


void ProjectPermissionContext::LookupRolesOfUser(std::set<std::string>& projectsAsInstructor,
                                                 std::set<std::string>& projectsAsLearner,
                                                 const std::string& userId) const
{
  DocumentOrientedDatabase::Iterator iterator(projects_);

  while (iterator.Next())
  {
    const Project& project = dynamic_cast<const Project&>(iterator.GetDocument());

    if (project.IsInstructor(userId))
    {
      projectsAsInstructor.insert(iterator.GetKey());
    }

    if (project.IsLearner(userId))
    {
      projectsAsLearner.insert(iterator.GetKey());
    }
  }
}


bool ProjectPermissionContext::LookupProjectFromLtiContext(std::string& projectId /* out */,
                                                           int64_t ltiContextId /* in */) const
{
  DocumentOrientedDatabase::Iterator iterator(projects_);

  // This loop could be optimized using an index, but there will
  // only be a few projects, so we keep things simple
  while (iterator.Next())
  {
    const Project& project = dynamic_cast<const Project&>(iterator.GetDocument());
    if (project.HasLtiContextId() &&
        project.GetLtiContextId() == boost::lexical_cast<std::string>(ltiContextId))
    {
      projectId = iterator.GetKey();
      return true;
    }
  }

  return false;
}
