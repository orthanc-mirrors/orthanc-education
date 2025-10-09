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

#include "../EducationEnumerations.h"

#include <Enumerations.h>

#include <boost/noncopyable.hpp>
#include <map>
#include <stdint.h>
#include <vector>


class AuthenticatedUser;


class IPermissionContext : public boost::noncopyable
{
public:
  virtual ~IPermissionContext()
  {
  }

  virtual void LookupRolesOfUser(std::set<std::string>& projectsAsInstructor,
                                 std::set<std::string>& projectsAsLearner,
                                 const std::string& userId) const = 0;

  virtual bool LookupProjectFromLtiContext(std::string& projectId /* out */,
                                           int64_t ltiContextId /* in */) const = 0;


  class IFactory : public boost::noncopyable
  {
  public:
    virtual ~IFactory()
    {
    }

    /**
     * This method must be thread-safe, as it can be invoked
     * simultaneously by multiple threads. However, the returned
     * "IPermissionContext" will be local to the calling thread.
     **/
    virtual IPermissionContext* CreateContext() const = 0;
  };
};
