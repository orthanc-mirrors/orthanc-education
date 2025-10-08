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

#include <set>
#include <string>

enum ViewerType
{
  // The order of the enum values will govern the viewer that is selected by default
  ViewerType_StoneWebViewer,
  ViewerType_VolView,
  ViewerType_OHIF_Basic,
  ViewerType_OHIF_VolumeRendering,
  ViewerType_OHIF_TumorVolume,
  ViewerType_OHIF_Segmentation,
  ViewerType_WholeSlideImaging
};

enum ProjectPolicy
{
  ProjectPolicy_Hidden,  // Only accessible to administrators and instructors
  ProjectPolicy_Active,  // Accessible to registered learners
  ProjectPolicy_Public   // For MOOC
};

enum Role
{
  Role_Administrator,  // For platform administrators
  Role_Standard,       // Standard user (either instructor or learner)
  Role_Guest           // Anonymous user (for public projects)
};

enum CookieSameSite
{
  CookieSameSite_Lax,
  CookieSameSite_None
};

enum AuthenticationMode
{
  AuthenticationMode_None,
  AuthenticationMode_Login,
  AuthenticationMode_RestrictedHttpHeader,
  AuthenticationMode_HttpHeader
};

enum AuthorizationStatus
{
  AuthorizationStatus_Forbidden,
  AuthorizationStatus_GrantedWithoutPayload,
  AuthorizationStatus_GrantedWithPayload   // Forward the authentication payload to the callback (slower)
};

enum ProjectAccessMode
{
  ProjectAccessMode_None,
  ProjectAccessMode_ReadOnly,
  ProjectAccessMode_Writable
};


const char* EnumerationToString(ViewerType viewer);

ViewerType ParseViewerType(const std::string& viewer);

const char* GetViewerDescription(ViewerType viewer);

const char* EnumerationToString(Role role);

Role ParseRole(const std::string& role);

const char* EnumerationToString(ProjectPolicy policy);

ProjectPolicy ParseProjectPolicy(const std::string& role);

const char* EnumerationToString(CookieSameSite sameSite);

AuthenticationMode ParseAuthenticationMode(const std::string& mode);
