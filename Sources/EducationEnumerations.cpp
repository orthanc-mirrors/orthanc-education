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


#include "EducationEnumerations.h"

#include <OrthancException.h>


const char* EnumerationToString(ViewerType viewer)
{
  switch (viewer)
  {
  case ViewerType_StoneWebViewer:
    return "stone";

  case ViewerType_WholeSlideImaging:
    return "wsi";

  case ViewerType_VolView:
    return "volview";

  case ViewerType_OHIF_Basic:
    return "ohif-basic";

  case ViewerType_OHIF_VolumeRendering:
    return "ohif-volume";

  case ViewerType_OHIF_TumorVolume:
    return "ohif-tumor";

  case ViewerType_OHIF_Segmentation:
    return "ohif-segmentation";

  default:
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
}


ViewerType ParseViewerType(const std::string& viewer)
{
  if (viewer == "stone")
  {
    return ViewerType_StoneWebViewer;
  }
  else if (viewer == "wsi")
  {
    return ViewerType_WholeSlideImaging;
  }
  else if (viewer == "volview")
  {
    return ViewerType_VolView;
  }
  else if (viewer == "ohif-basic")
  {
    return ViewerType_OHIF_Basic;
  }
  else if (viewer == "ohif-volume")
  {
    return ViewerType_OHIF_VolumeRendering;
  }
  else if (viewer == "ohif-tumor")
  {
    return ViewerType_OHIF_TumorVolume;
  }
  else if (viewer == "ohif-segmentation")
  {
    return ViewerType_OHIF_Segmentation;
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
}


const char* GetViewerDescription(ViewerType viewer)
{
  switch (viewer)
  {
  case ViewerType_StoneWebViewer:
    return "Stone Web viewer";

  case ViewerType_WholeSlideImaging:
    return "Whole-slide imaging";

  case ViewerType_VolView:
    return "Kitware Volview";

  case ViewerType_OHIF_Basic:
    return "OHIF - Basic viewer";

  case ViewerType_OHIF_VolumeRendering:
    return "OHIF - Volume rendering";

  case ViewerType_OHIF_TumorVolume:
    return "OHIF - Total metabolic tumor volume";

  case ViewerType_OHIF_Segmentation:
    return "OHIF - Segmentation";

  default:
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
}


const char* EnumerationToString(Role role)
{
  switch (role)
  {
  case Role_Administrator:
    return "admin";

  case Role_Standard:
    return "standard";

  case Role_Guest:
    return "guest";

  default:
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
}


Role ParseRole(const std::string& role)
{
  if (role == "admin")
  {
    return Role_Administrator;
  }
  else if (role == "standard")
  {
    return Role_Standard;
  }
  else if (role == "guest")
  {
    return Role_Guest;
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
}


const char* EnumerationToString(ProjectPolicy policy)
{
  switch (policy)
  {
  case ProjectPolicy_Hidden:
    return "hidden";

  case ProjectPolicy_Active:
    return "active";

  case ProjectPolicy_Public:
    return "public";

  default:
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
}


ProjectPolicy ParseProjectPolicy(const std::string& s)
{
  if (s == "hidden")
  {
    return ProjectPolicy_Hidden;
  }
  else if (s == "active")
  {
    return ProjectPolicy_Active;
  }
  else if (s == "public")
  {
    return ProjectPolicy_Public;
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
}


const char* EnumerationToString(CookieSameSite sameSite)
{
  switch (sameSite)
  {
  case CookieSameSite_Lax:
    return "Lax";

  case CookieSameSite_None:
    return "None";

  default:
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
}


AuthenticationMode ParseAuthenticationMode(const std::string& s)
{
  if (s == "None")
  {
    return AuthenticationMode_None;
  }
  else if (s == "Login")
  {
    return AuthenticationMode_Login;
  }
  else if (s == "RestrictedHttpHeader")
  {
    return AuthenticationMode_RestrictedHttpHeader;
  }
  else if (s == "HttpHeader")
  {
    return AuthenticationMode_HttpHeader;
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
}
