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

#include "Models/Project.h"

#include <Enumerations.h>


static const std::string LABEL_PREFIX = "education-";

static const char* const METADATA_INFO = "9520";
static const char* const METADATA_PREVIEW = "9521";


namespace OrthancDatabase
{
  class IProjectGranter : public boost::noncopyable
  {
  public:
    virtual ~IProjectGranter()
    {
    }

    /**
     * This method must answer the question: Given the user that is
     * currently authenticated, is this user allowed to access one of
     * the listed projects?
     **/
    virtual bool HasAccessToSomeProject(const std::set<std::string>& projectIds) const = 0;
  };

  std::string GenerateStudyViewerUrl(ViewerType viewer,
                                     const std::string& studyId,
                                     const std::string& studyInstanceUid,
                                     const std::string& description);

  std::string GenerateSeriesViewerUrl(ViewerType viewer,
                                      const std::string& seriesId,
                                      const std::string& studyInstanceUid,
                                      const std::string& seriesInstanceUid,
                                      const std::string& description);

  std::string GenerateInstanceViewerUrl(ViewerType viewer,
                                        const std::string& instanceId,
                                        const std::string& studyInstanceUid,
                                        const std::string& seriesInstanceUid,
                                        const std::string& sopInstanceUid,
                                        const std::string& description);

  std::string GenerateViewerUrl(ViewerType viewer,
                                const std::map<std::string, std::string>& resource);

  std::string GenerateViewerUrl(ViewerType viewer,
                                const Json::Value& resource);

  void ListAllStudies(Json::Value& target);

  void ListUnusedStudies(Json::Value& target,
                         const std::set<std::string>& allProjectIds);

  void ListUnusedSeries(Json::Value& target,
                        const std::set<std::string>& allProjectIds);

  void FindResourcesInProject(Json::Value& target,
                              const std::string& projectId);

  void FormatProjectWithResources(Json::Value& target,
                                  const std::string& projectId,
                                  const Project& project);

  bool IsGrantedResource(const IProjectGranter& granter,
                         Orthanc::ResourceType level,
                         const std::string& resourceId);

  bool IsGrantedDicomWeb(const IProjectGranter& granter,
                         const std::vector<std::string>& path,
                         const std::map<std::string, std::string>& getArguments);

  // "input" could be an Orthanc identifier, a DICOMweb identifier, or a path in the REST API
  bool LookupResourceByUserInput(Orthanc::ResourceType& level,
                                 std::string& resourceId,
                                 const std::string& input);
}
