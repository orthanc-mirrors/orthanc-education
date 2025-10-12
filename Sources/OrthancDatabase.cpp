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


#include "OrthancDatabase.h"

#include "EducationConfiguration.h"
#include "HttpToolbox.h"

#include <OrthancPluginCppWrapper.h>
#include <SerializationToolbox.h>
#include <Toolbox.h>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/regex.hpp>
#include <cassert>
#include <list>


static std::string FormatResourcePath(Orthanc::ResourceType level,
                                      const std::string& resourceId)
{
  switch (level)
  {
    case Orthanc::ResourceType_Patient:
      return "/patients/" + resourceId;

    case Orthanc::ResourceType_Study:
      return "/studies/" + resourceId;

    case Orthanc::ResourceType_Series:
      return "/series/" + resourceId;

    case Orthanc::ResourceType_Instance:
      return "/instances/" + resourceId;

    default:
      throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
}


enum ProjectsConstraint
{
  ProjectsConstraint_Ignored, // Look for all the DICOM resources, independently of their associated projects
  ProjectsConstraint_Any,     // Look for DICOM resources associated with a given subset of projects
  ProjectsConstraint_None     // Look for DICOM resources that are not associated with projects
};


static void ExecuteFind(Json::Value& resources,
                        Orthanc::ResourceType level,
                        ProjectsConstraint constraint,
                        const std::set<std::string>& projects)
{
  Json::Value labels = Json::arrayValue;
  for (std::set<std::string>::const_iterator it = projects.begin(); it != projects.end(); ++it)
  {
    labels.append(LABEL_PREFIX + *it);
  }

  Json::Value responseContent = Json::arrayValue;
  responseContent.append("Labels");
  responseContent.append("Metadata");

  std::list<std::string> titleTags;
  Json::Value requestedTags = Json::arrayValue;

  switch (level)
  {
    case Orthanc::ResourceType_Study:
      requestedTags.append("StudyInstanceUID");
      titleTags.push_back("PatientName");
      titleTags.push_back("StudyDescription");
      break;

    case Orthanc::ResourceType_Series:
      requestedTags.append("StudyInstanceUID");
      requestedTags.append("SeriesInstanceUID");
      titleTags.push_back("PatientName");
      titleTags.push_back("StudyDescription");
      titleTags.push_back("SeriesDescription");
      break;

    case Orthanc::ResourceType_Instance:
      requestedTags.append("StudyInstanceUID");
      requestedTags.append("SeriesInstanceUID");
      requestedTags.append("SOPInstanceUID");
      titleTags.push_back("PatientName");
      titleTags.push_back("StudyDescription");
      titleTags.push_back("SeriesDescription");
      titleTags.push_back("InstanceNumber");
      break;

    default:
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }

  for (std::list<std::string>::const_iterator it = titleTags.begin(); it != titleTags.end(); ++it)
  {
    requestedTags.append(*it);
  }

  Json::Value request;

  switch (constraint)
  {
  case ProjectsConstraint_Ignored:
    break;

  case ProjectsConstraint_Any:
    request["Labels"] = labels;
    request["LabelsConstraint"] = "Any";
    break;

  case ProjectsConstraint_None:
    request["Labels"] = labels;
    request["LabelsConstraint"] = "None";

    if (level == Orthanc::ResourceType_Series)
    {
      responseContent.append("Parent");
    }

    break;

  default:
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }

  request["Level"] = Orthanc::EnumerationToString(level);
  request["Query"] = Json::objectValue;
  request["Expand"] = true;
  request["ResponseContent"] = responseContent;
  request["RequestedTags"] = requestedTags;

  Json::Value response;
  if (!OrthancPlugins::RestApiPost(response, "/tools/find", request, false) ||
      response.type() != Json::arrayValue)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }

  for (Json::Value::ArrayIndex i = 0; i < response.size(); i++)
  {
    std::map<std::string, std::string> metadata;
    Orthanc::SerializationToolbox::ReadMapOfStrings(metadata, response[i], "Metadata");

    std::map<std::string, std::string> resourceTags;
    Orthanc::SerializationToolbox::ReadMapOfStrings(resourceTags, response[i], "RequestedTags");

    std::string title;

    std::map<std::string, std::string>::const_iterator found = metadata.find(METADATA_INFO);
    if (found != metadata.end())
    {
      Json::Value info;
      if (Orthanc::Toolbox::ReadJson(info, found->second))
      {
        title = Orthanc::SerializationToolbox::ReadString(info, "title", "");
      }
    }

    if (title.empty())
    {
      for (std::list<std::string>::const_iterator it = titleTags.begin(); it != titleTags.end(); ++it)
      {
        std::map<std::string, std::string>::const_iterator found = resourceTags.find(*it);
        if (found != resourceTags.end())
        {
          if (!title.empty())
          {
            title += " - ";
          }

          title += found->second;
        }
      }
    }

    std::list<std::string> labels;
    Orthanc::SerializationToolbox::ReadListOfStrings(labels, response[i], "Labels");

    Json::Value projects = Json::arrayValue;

    for (std::list<std::string>::const_iterator it = labels.begin(); it != labels.end(); ++it)
    {
      if (boost::starts_with(*it, LABEL_PREFIX))
      {
        projects.append(it->substr(LABEL_PREFIX.size()));
      }
    }

    const std::string resourceId = response[i]["ID"].asString();

    Json::Value resource;
    resource["level"] = Orthanc::EnumerationToString(level);
    resource["resource-id"] = resourceId;
    resource["series-instance-uid"] = HttpToolbox::ReadOptionalString(resourceTags, "SeriesInstanceUID", "");
    resource["sop-instance-uid"] = HttpToolbox::ReadOptionalString(resourceTags, "SOPInstanceUID", "");
    resource["study-instance-uid"] = HttpToolbox::ReadMandatoryString(resourceTags, "StudyInstanceUID");
    resource["title"] = title;
    resource["projects"] = projects;

    switch (level)
    {
      case Orthanc::ResourceType_Study:
        resource["preview_url"] = "../api/preview-study/" + resourceId;
        break;

      case Orthanc::ResourceType_Series:
        resource["preview_url"] = "../api/preview-series/" + resourceId;
        break;

      case Orthanc::ResourceType_Instance:
        resource["preview_url"] = "../api/preview-instance/" + resourceId;
        break;

      default:
        throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }

    resources.append(resource);
  }
}


static void ExecuteFindForProject(Json::Value& resources,
                                 Orthanc::ResourceType level,
                                 const std::string& projectId)
{
  std::set<std::string> projects;
  projects.insert(projectId);
  ExecuteFind(resources, level, ProjectsConstraint_Any, projects);
}


static bool LookupResource(std::string& resourceId,
                           std::map<Orthanc::DicomTag, std::string>& tags,
                           Orthanc::ResourceType level)
{
  Json::Value query;

  for (std::map<Orthanc::DicomTag, std::string>::const_iterator it = tags.begin(); it != tags.end(); ++it)
  {
    query[it->first.Format()] = it->second;
  }

  Json::Value request;
  request["Level"] = Orthanc::EnumerationToString(level);
  request["Query"] = query;
  request["Expand"] = false;

  Json::Value response;
  if (OrthancPlugins::RestApiPost(response, "/tools/find", request, false))
  {
    if (response.type() != Json::arrayValue)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }
    else if (response.size() == 1)
    {
      if (response[0].type() != Json::stringValue)
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
      }
      else
      {
        resourceId = response[0].asString();
        return true;
      }
    }
    else
    {
      return false;
    }
  }
  else
  {
    return false;
  }
}


static bool IsGrantedDicomWebStudy(const OrthancDatabase::IProjectGranter& granter,
                                   const std::string& studyInstanceUid)
{
  static const char* const KEY_SERIES = "Series";

  std::map<Orthanc::DicomTag, std::string> tags;
  tags[Orthanc::DICOM_TAG_STUDY_INSTANCE_UID] = studyInstanceUid;

  std::string resourceId;
  if (LookupResource(resourceId, tags, Orthanc::ResourceType_Study))
  {
    if (OrthancDatabase::IsGrantedResource(granter, Orthanc::ResourceType_Study, resourceId))
    {
      return true;
    }
    else
    {
      // This happens if the learner is granted access at the series
      // level, but not at the study level

      Json::Value study;
      if (OrthancPlugins::RestApiGet(study, "/studies/" + resourceId, false))
      {
        if (!study.isMember(KEY_SERIES) ||
            study[KEY_SERIES].type() != Json::arrayValue)
        {
          throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
        }

        for (Json::Value::ArrayIndex i = 0; i < study[KEY_SERIES].size(); i++)
        {
          if (study[KEY_SERIES][i].type() != Json::stringValue)
          {
            throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
          }
          else if (OrthancDatabase::IsGrantedResource(granter, Orthanc::ResourceType_Series, study[KEY_SERIES][i].asString()))
          {
            return true;
          }
        }

        return false;
      }
      else
      {
        return false;
      }
    }
  }
  else
  {
    return false;
  }
}


static bool IsGrantedDicomWebSeries(const OrthancDatabase::IProjectGranter& granter,
                                    const std::string& studyInstanceUid,
                                    const std::string& seriesInstanceUid)
{
  std::map<Orthanc::DicomTag, std::string> tags;
  tags[Orthanc::DICOM_TAG_STUDY_INSTANCE_UID] = studyInstanceUid;

  std::string resourceId;
  if (LookupResource(resourceId, tags, Orthanc::ResourceType_Study) &&
      OrthancDatabase::IsGrantedResource(granter, Orthanc::ResourceType_Study, resourceId))
  {
    // The learner has access to the full study
    return true;
  }

  tags[Orthanc::DICOM_TAG_SERIES_INSTANCE_UID] = seriesInstanceUid;
  return (LookupResource(resourceId, tags, Orthanc::ResourceType_Series) &&
          OrthancDatabase::IsGrantedResource(granter, Orthanc::ResourceType_Series, resourceId));
}


static bool LookupStudyInstanceUid(std::string& resourceId,
                                   const std::string& input)
{
  OrthancPlugins::OrthancString s;
  s.Assign(OrthancPluginLookupStudy(OrthancPlugins::GetGlobalContext(), input.c_str()));

  if (s.IsNullOrEmpty())
  {
    return false;
  }
  else
  {
    s.ToString(resourceId);
    return true;
  }
}


static bool LookupSeriesInstanceUid(std::string& resourceId,
                                    const std::string& input)
{
  OrthancPlugins::OrthancString s;
  s.Assign(OrthancPluginLookupSeries(OrthancPlugins::GetGlobalContext(), input.c_str()));

  if (s.IsNullOrEmpty())
  {
    return false;
  }
  else
  {
    s.ToString(resourceId);
    return true;
  }
}


static bool LookupSopInstanceUid(std::string& resourceId,
                                 const std::string& input)
{
  OrthancPlugins::OrthancString s;
  s.Assign(OrthancPluginLookupInstance(OrthancPlugins::GetGlobalContext(), input.c_str()));

  if (s.IsNullOrEmpty())
  {
    return false;
  }
  else
  {
    s.ToString(resourceId);
    return true;
  }
}


namespace OrthancDatabase
{
  std::string GenerateStudyViewerUrl(ViewerType viewer,
                                     const std::string& studyId,
                                     const std::string& studyInstanceUid)
  {
    switch (viewer)
    {
      case ViewerType_StoneWebViewer:
        return "stone-webviewer/index.html?study=" + studyInstanceUid;

      case ViewerType_VolView:
        return "volview/index.html?names=[archive.zip]&urls=[../studies/" + studyId + "/archive]";

      case ViewerType_OHIF_Basic:
        return "ohif/viewer?StudyInstanceUIDs=" + studyInstanceUid;

      case ViewerType_OHIF_VolumeRendering:
        return "ohif/viewer?hangingprotocolId=mprAnd3DVolumeViewport&StudyInstanceUIDs=" + studyInstanceUid;

      case ViewerType_OHIF_TumorVolume:
        return "ohif/tmtv?StudyInstanceUIDs=" + studyInstanceUid;

      case ViewerType_OHIF_Segmentation:
        return "ohif/segmentation?StudyInstanceUIDs=" + studyInstanceUid;

      default:
        throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
    }
  }


  std::string GenerateSeriesViewerUrl(ViewerType viewer,
                                      const std::string& seriesId,
                                      const std::string& studyInstanceUid,
                                      const std::string& seriesInstanceUid)
  {
    switch (viewer)
    {
      case ViewerType_StoneWebViewer:
        return "stone-webviewer/index.html?study=" + studyInstanceUid + "&series=" + seriesInstanceUid;

      case ViewerType_WholeSlideImaging:
        return "wsi/app/viewer.html?series=" + seriesId;

      case ViewerType_VolView:
        return "volview/index.html?names=[archive.zip]&urls=[../series/" + seriesId + "/archive]";

      default:
        throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
    }
  }


  std::string GenerateInstanceViewerUrl(ViewerType viewer,
                                        const std::string& instanceId,
                                        const std::string& studyInstanceUid,
                                        const std::string& seriesInstanceUid,
                                        const std::string& sopInstanceUid)
  {
    switch (viewer)
    {
      case ViewerType_WholeSlideImaging:
        return "wsi/app/viewer.html?instance=" + instanceId;

      default:
        throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
    }
  }


  std::string GenerateViewerUrl(ViewerType viewer,
                                const std::map<std::string, std::string>& resource)
  {
    const std::string levelString = HttpToolbox::ReadMandatoryString(resource, "level");
    const Orthanc::ResourceType level = Orthanc::StringToResourceType(levelString.c_str());

    switch (level)
    {
      case Orthanc::ResourceType_Study:
        return GenerateStudyViewerUrl(viewer,
                                      HttpToolbox::ReadMandatoryString(resource, "resource-id"),
                                      HttpToolbox::ReadMandatoryString(resource, "study-instance-uid"));

      case Orthanc::ResourceType_Series:
        return GenerateSeriesViewerUrl(viewer,
                                       HttpToolbox::ReadMandatoryString(resource, "resource-id"),
                                       HttpToolbox::ReadMandatoryString(resource, "study-instance-uid"),
                                       HttpToolbox::ReadMandatoryString(resource, "series-instance-uid"));

      case Orthanc::ResourceType_Instance:
        return GenerateInstanceViewerUrl(viewer,
                                         HttpToolbox::ReadMandatoryString(resource, "resource-id"),
                                         HttpToolbox::ReadMandatoryString(resource, "study-instance-uid"),
                                         HttpToolbox::ReadMandatoryString(resource, "series-instance-uid"),
                                         HttpToolbox::ReadMandatoryString(resource, "sop-instance-uid"));

      default:
        throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
    }
  }


  std::string GenerateViewerUrl(ViewerType viewer,
                                const Json::Value& resource)
  {
    std::map<std::string, std::string> args;

    if (resource.type() != Json::objectValue)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
    }

    Json::Value::Members members = resource.getMemberNames();
    for (size_t i = 0; i < members.size(); i++)
    {
      const Json::Value& value = resource[members[i]];
      if (value.type() == Json::stringValue)
      {
        args[members[i]] = value.asString();
      }
    }

    return GenerateViewerUrl(viewer, args);
  }


  void ListAllStudies(Json::Value& target)
  {
    target.clear();
    std::set<std::string> projects;
    ExecuteFind(target, Orthanc::ResourceType_Study, ProjectsConstraint_Ignored, projects);
  }


  void ListUnusedStudies(Json::Value& target,
                         const std::set<std::string>& allProjectIds)
  {
    target.clear();
    ExecuteFind(target, Orthanc::ResourceType_Study, ProjectsConstraint_None, allProjectIds);
  }


  void ListUnusedSeries(Json::Value& target,
                        const std::set<std::string>& allProjectIds)
  {
    /**
     * An "unused DICOM series" is defined as a DICOM series that is
     * not associated with any project, and whose parent study is also
     * not associated with any project.
     **/

    // First, get the Study Instance UIDs of all the unused studies
    std::set<std::string> unusedStudies;

    {
      Json::Value studies;
      ExecuteFind(studies, Orthanc::ResourceType_Study, ProjectsConstraint_None, allProjectIds);

      for (Json::Value::ArrayIndex i = 0; i < studies.size(); i++)
      {
        assert(Orthanc::SerializationToolbox::ReadString(studies[i], "level") == "Study");
        unusedStudies.insert(Orthanc::SerializationToolbox::ReadString(studies[i], "study-instance-uid"));
      }
    }

    // Secondly, download all the series not associated with any project
    Json::Value series;
    ExecuteFind(series, Orthanc::ResourceType_Series, ProjectsConstraint_None, allProjectIds);

    // Thirdly, merge the two lists by computing their intersection
    target.clear();
    for (Json::Value::ArrayIndex i = 0; i < series.size(); i++)
    {
      const std::string studyInstanceUid = Orthanc::SerializationToolbox::ReadString(series[i], "study-instance-uid");
      std::set<std::string>::const_iterator found = unusedStudies.find(studyInstanceUid);
      if (found != unusedStudies.end())
      {
        target.append(series[i]);
      }
    }
  }


  void FindResourcesInProject(Json::Value& target,
                              const std::string& projectId)
  {
    target.clear();
    ExecuteFindForProject(target, Orthanc::ResourceType_Study, projectId);
    ExecuteFindForProject(target, Orthanc::ResourceType_Series, projectId);
    ExecuteFindForProject(target, Orthanc::ResourceType_Instance, projectId);
  }


  void FormatProjectWithResources(Json::Value& target,
                                  const std::string& projectId,
                                  const Project& project)
  {
    if (target.type() == Json::nullValue)
    {
      target = Json::objectValue;
    }
    else if (target.type() != Json::objectValue)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }

    target["name"] = project.GetName();
    target["description"] = project.GetDescription();
    target["policy"] = EnumerationToString(project.GetPolicy());
    target["primary_viewer"] = EnumerationToString(project.GetPrimaryViewer());

    std::set<ViewerType> viewers;
    project.GetAllViewers(viewers);
    HttpToolbox::FormatViewers(target["secondary_viewers"], viewers);

    Json::Value resources = Json::arrayValue;
    FindResourcesInProject(resources, projectId);
    target["resources"] = resources;
  }


  bool IsGrantedResource(const IProjectGranter& granter,
                         Orthanc::ResourceType level,
                         const std::string& resourceId)
  {
    std::set<std::string> projectIds;

    Json::Value labels;
    if (OrthancPlugins::RestApiGet(labels, FormatResourcePath(level, resourceId) + "/labels", false))
    {
      if (labels.type() != Json::arrayValue)
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
      }

      for (Json::Value::ArrayIndex i = 0; i < labels.size(); i++)
      {
        if (labels[i].type() != Json::stringValue)
        {
          throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
        }
        else
        {
          const std::string label = labels[i].asString();

          if (boost::starts_with(label, LABEL_PREFIX))
          {
            projectIds.insert(label.substr(LABEL_PREFIX.size()));
          }
        }
      }
    }

    return granter.HasAccessToSomeProject(projectIds);
  }


  bool IsGrantedDicomWeb(const OrthancDatabase::IProjectGranter& granter,
                         const std::vector<std::string>& path,
                         const std::map<std::string, std::string>& getArguments)
  {
    assert(path.size() >= 2 && path[0] == "dicom-web");

    /**
     * WADO-RS
     **/

    if (path.size() == 4 &&
        path[1] == "studies" &&
        path[3] == "series")
    {
      return IsGrantedDicomWebStudy(granter, path[2]);  // This is notably used by OHIF
    }

    if (path.size() == 6 &&
        path[1] == "studies" &&
        path[3] == "series" &&
        (path[5] == "metadata" ||
         path[5] == "rendered"))
    {
      return IsGrantedDicomWebSeries(granter, path[2], path[4]);
    }

    if (path.size() == 7 &&
        path[1] == "studies" &&
        path[3] == "series" &&
        path[5] == "instances")
    {
      return IsGrantedDicomWebSeries(granter, path[2], path[4]);
    }

    if (path.size() == 8 &&
        path[1] == "studies" &&
        path[3] == "series" &&
        path[5] == "instances" &&
        (path[7] == "metadata" ||
         path[7] == "rendered"))
    {
      return IsGrantedDicomWebSeries(granter, path[2], path[4]);
    }

    if (path.size() == 9 &&
        path[1] == "studies" &&
        path[3] == "series" &&
        path[5] == "instances" &&
        path[7] == "frames")
    {
      return IsGrantedDicomWebSeries(granter, path[2], path[4]);  // This is notably used by OHIF
    }

    if (path.size() == 10 &&
        path[1] == "studies" &&
        path[3] == "series" &&
        path[5] == "instances" &&
        path[7] == "frames" &&
        path[9] == "rendered")
    {
      return IsGrantedDicomWebSeries(granter, path[2], path[4]);
    }


    /**
     * QIDO-RS
     **/

    // NB: The keys of "getArguments" are converted to lower case by "::Authorize()"
    std::map<std::string, std::string>::const_iterator studyInstanceUid = getArguments.find("0020000d");
    if (studyInstanceUid == getArguments.end())
    {
      studyInstanceUid = getArguments.find("studyinstanceuid");  // This is notably used by OHIF
    }

    std::map<std::string, std::string>::const_iterator seriesInstanceUid = getArguments.find("0020000e");
    if (seriesInstanceUid == getArguments.end())
    {
      seriesInstanceUid = getArguments.find("seriesinstanceuid");
    }

    if (path.size() == 2 &&
        (path[1] == "studies" ||
         path[1] == "series") &&
        studyInstanceUid != getArguments.end())
    {
      return IsGrantedDicomWebStudy(granter, studyInstanceUid->second);
    }

    if (path.size() == 2 &&
        path[1] == "instances" &&
        studyInstanceUid != getArguments.end() &&
        seriesInstanceUid != getArguments.end())
    {
      return IsGrantedDicomWebSeries(granter, studyInstanceUid->second, seriesInstanceUid->second);
    }

    return false;
  }


  bool LookupResourceByUserInput(Orthanc::ResourceType& level,
                                 std::string& resourceId,
                                 const std::string& input)
  {
    bool couldBeIdentifier = !input.empty();
    for (size_t i = 0; i < input.size(); i++)
    {
      if (input[i] != '.' &&
          input[i] != '-' &&
          input[i] != '_' &&
          !(input[i] >= 'a' && input[i] <= 'z') &&
          !(input[i] >= 'A' && input[i] <= 'Z') &&
          !(input[i] >= '0' && input[i] <= '9'))
      {
        couldBeIdentifier = false;
        break;
      }
    }

    OrthancPlugins::OrthancString t;

    if (couldBeIdentifier)
    {
      // Lookup by Orthanc identifiers
      Json::Value v;
      if (OrthancPlugins::RestApiGet(v, "/studies/" + input, false))
      {
        level = Orthanc::ResourceType_Study;
        resourceId = input;
        return true;
      }

      if (OrthancPlugins::RestApiGet(v, "/series/" + input, false))
      {
        level = Orthanc::ResourceType_Series;
        resourceId = input;
        return true;
      }

      if (OrthancPlugins::RestApiGet(v, "/instances/" + input, false))
      {
        level = Orthanc::ResourceType_Instance;
        resourceId = input;
        return true;
      }

      // Lookup by DICOM identifers
      if (LookupStudyInstanceUid(resourceId, input))
      {
        level = Orthanc::ResourceType_Study;
        return true;
      }

      if (LookupSeriesInstanceUid(resourceId, input))
      {
        level = Orthanc::ResourceType_Series;
        return true;
      }

      if (LookupSopInstanceUid(resourceId, input))
      {
        level = Orthanc::ResourceType_Instance;
        return true;
      }
    }

    std::string base;
    if (EducationConfiguration::GetInstance().StartsWithPublicRoot(base, input))
    {
      Orthanc::Toolbox::UrlDecode(base);

      /**
       * Lookup for Stone Web viewer
       **/

      {
        // It is important to first look for series, as "study" is also included at the series level
        boost::regex pattern("/stone-webviewer/index.html?.*series=([0-9a-z.]+).*");

        boost::smatch what;
        if (regex_match(base, what, pattern) &&
            LookupSeriesInstanceUid(resourceId, what[1]))
        {
          level = Orthanc::ResourceType_Series;
          return true;
        }
      }

      {
        boost::regex pattern("/stone-webviewer/index.html?.*study=([0-9a-z.]+).*");

        boost::smatch what;
        if (regex_match(base, what, pattern) &&
            LookupStudyInstanceUid(resourceId, what[1]))
        {
          level = Orthanc::ResourceType_Study;
          return true;
        }
      }


      /**
       * Lookup for VolView
       **/

      Json::Value v;

      {
        boost::regex pattern("/volview/index.html?.*(/(studies|series)/[0-9a-z-]+)/archive.*");

        boost::smatch what;
        if (regex_match(base, what, pattern) &&
            OrthancPlugins::RestApiGet(v, what[1], false))
        {
          resourceId = what[3];

          if (what[2] == "studies")
          {
            level = Orthanc::ResourceType_Study;
            return true;
          }
          if (what[2] == "series")
          {
            level = Orthanc::ResourceType_Series;
            return true;
          }
          else
          {
            throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
          }
        }
      }


      /**
       * Lookup for OHIF
       **/

      {
        boost::regex pattern("/ohif/.+?.*StudyInstanceUIDs=([0-9a-z.]+).*");

        boost::smatch what;
        if (regex_match(base, what, pattern) &&
            LookupStudyInstanceUid(resourceId, what[1]))
        {
          level = Orthanc::ResourceType_Study;
          return true;
        }
      }


      /**
       * Lookup for whole-slide imaging
       **/

      {
        boost::regex pattern("/wsi/app/viewer.html?.*series=([0-9a-z-]+).*");

        boost::smatch what;
        if (regex_match(base, what, pattern) &&
            OrthancPlugins::RestApiGet(v, "/series/" + what[1], false))
        {
          resourceId = what[1];
          level = Orthanc::ResourceType_Study;
          return true;
        }
      }

      {
        boost::regex pattern("/wsi/app/viewer.html?.*instance=([0-9a-z-]+).*");

        boost::smatch what;
        if (regex_match(base, what, pattern) &&
            OrthancPlugins::RestApiGet(v, "/instances/" + what[1], false))
        {
          resourceId = what[1];
          level = Orthanc::ResourceType_Instance;
          return true;
        }
      }


      /**
       * Lookup for Orthanc Explorer
       **/

      {
        boost::regex pattern("/app/explorer.html#study?.*uuid=([0-9a-z-]+).*");

        boost::smatch what;
        if (regex_match(base, what, pattern) &&
            OrthancPlugins::RestApiGet(v, "/studies/" + what[1], false))
        {
          resourceId = what[1];
          level = Orthanc::ResourceType_Study;
          return true;
        }
      }

      {
        boost::regex pattern("/app/explorer.html#series?.*uuid=([0-9a-z-]+).*");

        boost::smatch what;
        if (regex_match(base, what, pattern) &&
            OrthancPlugins::RestApiGet(v, "/series/" + what[1], false))
        {
          resourceId = what[1];
          level = Orthanc::ResourceType_Series;
          return true;
        }
      }

      {
        boost::regex pattern("/app/explorer.html#instance?.*uuid=([0-9a-z-]+).*");

        boost::smatch what;
        if (regex_match(base, what, pattern) &&
            OrthancPlugins::RestApiGet(v, "/instances/" + what[1], false))
        {
          resourceId = what[1];
          level = Orthanc::ResourceType_Instance;
          return true;
        }
      }

      return false;
    }
    else
    {
      return false;
    }
  }
}
