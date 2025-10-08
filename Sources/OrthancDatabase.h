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

#include "Models/Project.h"
#include "Permissions/IPermissionContext.h"

#include <Enumerations.h>


static const std::string LABEL_PREFIX = "education-";

static const char* const METADATA_INFO = "9520";
static const char* const METADATA_PREVIEW = "9521";


namespace OrthancDatabase
{
  std::string GenerateStudyViewerUrl(ViewerType viewer,
                                     const std::string& studyId,
                                     const std::string& studyInstanceUid);

  std::string GenerateSeriesViewerUrl(ViewerType viewer,
                                      const std::string& seriesId,
                                      const std::string& studyInstanceUid,
                                      const std::string& seriesInstanceUid);

  std::string GenerateInstanceViewerUrl(ViewerType viewer,
                                        const std::string& instanceId,
                                        const std::string& studyInstanceUid,
                                        const std::string& seriesInstanceUid,
                                        const std::string& sopInstanceUid);

  std::string GenerateViewerUrl(ViewerType viewer,
                                const std::map<std::string, std::string>& resource);

  std::string GenerateViewerUrl(ViewerType viewer,
                                const Json::Value& resource);

  void FindResourcesInProject(Json::Value& target,
                              const std::string& projectId);

  void FormatProjectWithResources(Json::Value& target,
                                  const std::string& projectId,
                                  const Project& project);

  bool IsGrantedResource(const IPermissionContext& context,
                         const AuthenticatedUser& user,
                         Orthanc::ResourceType level,
                         const std::string& resourceId);

  bool IsGrantedDicomWeb(const IPermissionContext& context,
                         const AuthenticatedUser& user,
                         const std::vector<std::string>& path,
                         const std::map<std::string, std::string>& getArguments);

  // "input" could be an Orthanc identifier, a DICOMweb identifier, or a path in the REST API
  bool LookupResourceByUserInput(Orthanc::ResourceType& level,
                                 std::string& resourceId,
                                 const std::string& input);
}
