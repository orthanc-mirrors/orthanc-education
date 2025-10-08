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


#include "EducationRestApi.h"

#include "EducationConfiguration.h"
#include "LTI/LTIRoutes.h"
#include "OrthancDatabase.h"
#include "ProjectPermissionContext.h"
#include "RestApiRouter.h"

#include <MultiThreading/Semaphore.h>
#include <SerializationToolbox.h>
#include <SystemToolbox.h>

#include <boost/algorithm/string/predicate.hpp>
#include <cassert>


static const char* const COOKIE_USER_AUTH = "orthanc-education-user";


void ServeWebApplication(OrthancPluginRestOutput* output,
                         const std::string& url,
                         const OrthancPluginHttpRequest* request,
                         const AuthenticatedUser& user)
{
  assert(user.GetRole() == Role_Guest);

  static const std::string PREFIX = "/education/app/";
  if (!boost::starts_with(url, PREFIX))
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
  }

  const std::string filename = std::string(url).substr(PREFIX.length());
  const Orthanc::MimeType mime = Orthanc::SystemToolbox::AutodetectMimeType(filename);

  std::string content;
  HttpToolbox::GetWebApplicationResource(content, filename);

  OrthancPluginAnswerBuffer(OrthancPlugins::GetGlobalContext(), output,
                            content.c_str(), content.size(), Orthanc::EnumerationToString(mime));
}


void DoLogin(OrthancPluginRestOutput* output,
             const std::string& url,
             const OrthancPluginHttpRequest* request,
             const AuthenticatedUser& oldUser,
             const Json::Value& body)
{
  assert(oldUser.GetRole() == Role_Guest);

  const std::string username = Orthanc::SerializationToolbox::ReadString(body, "username");
  const std::string password = Orthanc::SerializationToolbox::ReadString(body, "password");

  std::unique_ptr<AuthenticatedUser> user(EducationConfiguration::GetInstance().DoLoginAuthentication(username, password));

  if (user.get() == NULL)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_Unauthorized);
  }
  else
  {
    std::string token;
    user->ForgeJWT(token, EducationConfiguration::GetInstance().GetLtiContext(),
                   EducationConfiguration::GetInstance().GetMaxLoginAgeSeconds());

    EducationConfiguration::GetInstance().GetLtiContext().CloseSession(output);
    HttpToolbox::SetCookie(output, COOKIE_USER_AUTH, token, CookieSameSite_Lax);

    Json::Value answer;
    HttpToolbox::AnswerJson(output, answer);
  }
}


void DoLogout(OrthancPluginRestOutput* output,
              const std::string& url,
              const OrthancPluginHttpRequest* request,
              const AuthenticatedUser& user)
{
  assert(user.GetRole() == Role_Guest);

  EducationConfiguration::GetInstance().GetLtiContext().CloseSession(output);
  HttpToolbox::ClearCookie(output, COOKIE_USER_AUTH, CookieSameSite_Lax);
  ClearLTICookie(output);

  // We manually reimplement "OrthancPluginRedirect()", otherwise "Set-Cookie" has no effect
  OrthancPluginSetHttpHeader(OrthancPlugins::GetGlobalContext(), output, "Location", ".." /* redirect to the root */);
  OrthancPluginSendHttpStatusCode(OrthancPlugins::GetGlobalContext(), output, 302);
}


void GenerateListProjectUrl(OrthancPluginRestOutput* output,
                            const std::string& url,
                            const OrthancPluginHttpRequest* request,
                            const AuthenticatedUser& user,
                            const Json::Value& body)
{
  assert(user.GetRole() == Role_Guest);

  const std::string projectId = Orthanc::SerializationToolbox::ReadString(body, "project");

  std::string s;
  Orthanc::Toolbox::UriEncode(s, projectId);

  const std::string listUrl = "education/app/list-projects.html?open-project-id=" + s;

  Json::Value answer;
  answer["relative_url"] = listUrl;

  std::string absolute;
  if (EducationConfiguration::GetInstance().GetAbsoluteUrl(absolute, listUrl))
  {
    answer["absolute_url"] = absolute;
  }

  HttpToolbox::AnswerJson(output, answer);
}


void GenerateViewerUrlFromResource(OrthancPluginRestOutput* output,
                                   const std::string& url,
                                   const OrthancPluginHttpRequest* request,
                                   const AuthenticatedUser& user,
                                   const Json::Value& body)
{
  assert(user.GetRole() == Role_Guest);

  const ViewerType viewer = ParseViewerType(Orthanc::SerializationToolbox::ReadString(body, "viewer"));

  Json::Value resource;
  if (!HttpToolbox::LookupJsonObject(resource, body, "resource"))
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
  }

  const std::string viewerUrl = OrthancDatabase::GenerateViewerUrl(viewer, resource);

  Json::Value answer;
  answer["relative_url"] = viewerUrl;

  std::string absolute;
  if (EducationConfiguration::GetInstance().GetAbsoluteUrl(absolute, viewerUrl))
  {
    answer["absolute_url"] = absolute;
  }

  HttpToolbox::AnswerJson(output, answer);
}


void GetUserProjects(OrthancPluginRestOutput* output,
                     const std::string& url,
                     const OrthancPluginHttpRequest* request,
                     const AuthenticatedUser& user)
{
  if (user.GetRole() != Role_Administrator &&
      user.GetRole() != Role_Standard)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ForbiddenAccess);
  }

  // List all the projects
  Json::Value projects = Json::objectValue;

  {
    DocumentOrientedDatabase::Iterator iterator(ProjectPermissionContext::GetProjects());

    while (iterator.Next())
    {
      const Project& project = iterator.GetDocument<Project>();
      const ProjectAccessMode mode = ProjectPermissionContext::GetProjectAccessMode(user, iterator.GetKey(), project);

      Json::Value item;

      if (mode == ProjectAccessMode_Writable)
      {
        item["role"] = "instructor";
      }
      else if (EducationConfiguration::GetInstance().IsListProjectsAsLearner() &&
               mode == ProjectAccessMode_ReadOnly)
      {
        item["role"] = "learner";
      }
      else
      {
        continue;
      }

      OrthancDatabase::FormatProjectWithResources(item, iterator.GetKey(), project);
      projects[iterator.GetKey()] = item;
    }
  }

  Json::Value answer = Json::objectValue;
  user.Serialize(answer["user"]);
  answer["projects"] = projects;

  HttpToolbox::AnswerJson(output, answer);
}


static const char* const GetHomepage(Role role)
{
  switch (role)
  {
  case Role_Administrator:
    // Redirect to the dashboard if the user is already logged as an administrator
    return "education/app/dashboard.html";

  case Role_Standard:
    return "education/app/list-projects.html";

  case Role_Guest:
    // By default, redirect to the login page
    return "education/app/login.html";

  default:
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
}


void RedirectRoot(OrthancPluginRestOutput* output,
                  const std::string& url,
                  const OrthancPluginHttpRequest* request,
                  const AuthenticatedUser& user)
{
  const std::string homepage = GetHomepage(user.GetRole());
  OrthancPluginRedirect(OrthancPlugins::GetGlobalContext(), output, homepage.c_str());
}


void ServeConfiguration(OrthancPluginRestOutput* output,
                        const std::string& url,
                        const OrthancPluginHttpRequest* request,
                        const AuthenticatedUser& user)
{
  Json::Value config;
  user.Serialize(config["user"]);

  if (user.GetRole() == Role_Administrator)
  {
    // This information is available to "dashboard.html", but not to "list-projects.html"
    config["has_orthanc_explorer_2"] = EducationConfiguration::GetInstance().HasPluginOrthancExplorer2();
    config["lti_client_id"] = EducationConfiguration::GetInstance().GetLtiClientId();
    config["lti_platform_url"] = EducationConfiguration::GetInstance().GetLtiPlatformUrl();
    config["lti_platform_keys_url"] = EducationConfiguration::GetInstance().GetLtiPlatformKeysUrl();
    config["lti_platform_redirection_url"] = EducationConfiguration::GetInstance().GetLtiPlatformRedirectionUrl();
  }

  std::set<ViewerType> viewers;
  EducationConfiguration::GetInstance().ListAvailableViewers(viewers);
  HttpToolbox::FormatViewers(config["viewers"], viewers);

  if (viewers.empty() ||
      viewers.find(ViewerType_StoneWebViewer) != viewers.end())
  {
    config["default_viewer"] = EnumerationToString(ViewerType_StoneWebViewer);
  }
  else
  {
    config["default_viewer"] = EnumerationToString(*viewers.begin());
  }

  config["label_prefix"] = LABEL_PREFIX;

  HttpToolbox::AnswerJson(output, config);
}


void ServeLogin(OrthancPluginRestOutput* output,
                const std::string& url,
                const OrthancPluginHttpRequest* request,
                const AuthenticatedUser& user)
{
  if (user.GetRole() == Role_Administrator ||
      user.GetRole() == Role_Standard)
  {
    // Special case: If the user is already logged in, redirect to the homepage
    std::string url = Orthanc::Toolbox::JoinUri("../..", GetHomepage(user.GetRole()));
    OrthancPluginRedirect(OrthancPlugins::GetGlobalContext(), output, url.c_str());
  }
  else
  {
    std::string content;
    HttpToolbox::GetWebApplicationResource(content, "login.html");

    OrthancPluginAnswerBuffer(OrthancPlugins::GetGlobalContext(), output,
                              content.c_str(), content.size(), Orthanc::EnumerationToString(Orthanc::MimeType_Html));
  }
}


static std::string GetJsonString(const Json::Value& json)
{
  if (json.type() == Json::stringValue)
  {
    return json.asString();
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
  }
}


void ChangeProjectParameter(OrthancPluginRestOutput* output,
                            const std::string& url,
                            const OrthancPluginHttpRequest* request,
                            const AuthenticatedUser& user)
{
  const std::string key(request->groups[0]);
  const std::string property(request->groups[1]);

  std::unique_ptr<Project> project(ProjectPermissionContext::GetProjects().CloneDocument<Project>(key));

  if (ProjectPermissionContext::GetProjectAccessMode(user, key, *project) != ProjectAccessMode_Writable)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ForbiddenAccess);
  }

  if (user.GetRole() != Role_Administrator &&
      property != "policy" &&
      property != "primary-viewer" &&
      property != "secondary-viewer")
  {
    // Other properties can only be changed by the administrator
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ForbiddenAccess);
  }

  if (request->method == OrthancPluginHttpMethod_Put)
  {
    Json::Value body;
    if (!Orthanc::Toolbox::ReadJson(body, request->body, request->bodySize))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
    }
    else
    {
      if (property == "name")
      {
        project->SetName(GetJsonString(body));
      }
      else if (property == "description")
      {
        project->SetDescription(GetJsonString(body));
      }
      else if (property == "policy")
      {
        project->SetPolicy(ParseProjectPolicy(GetJsonString(body)));
      }
      else if (property == "primary-viewer")
      {
        project->SetPrimaryViewer(ParseViewerType(GetJsonString(body)));
      }
      else if (property == "secondary-viewers")
      {
        std::set<std::string> items;
        Orthanc::SerializationToolbox::ReadSetOfStrings(items, body);

        std::set<ViewerType> viewers;
        for (std::set<std::string>::const_iterator it = items.begin(); it != items.end(); ++it)
        {
          viewers.insert(ParseViewerType(*it));
        }

        project->SetSecondaryViewers(viewers);
      }
      else if (property == "instructors")
      {
        std::set<std::string> items;
        Orthanc::SerializationToolbox::ReadSetOfStrings(items, body);
        project->SetInstructors(items);
      }
      else if (property == "learners")
      {
        std::set<std::string> items;
        Orthanc::SerializationToolbox::ReadSetOfStrings(items, body);
        project->SetLearners(items);
      }
      else if (property == "lti-context-id")
      {
        project->SetLtiContextId(GetJsonString(body));
      }
      else
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
      }
    }
  }
  else if (request->method == OrthancPluginHttpMethod_Delete)
  {
    if (property == "lti-context-id")
    {
      project->ClearLtiContextId();
    }
    else
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
    }
  }
  else
  {
    OrthancPluginSendMethodNotAllowed(OrthancPlugins::GetGlobalContext(), output, "PUT,DELETE");
    return;
  }

  ProjectPermissionContext::GetProjects().Store(key, project.release());

  HttpToolbox::AnswerText(output, "");
}


static Orthanc::Semaphore previewThrottler_(8);


template <Orthanc::ResourceType level>
void GeneratePreview(OrthancPluginRestOutput* output,
                     const std::string& url,
                     const OrthancPluginHttpRequest* request,
                     const AuthenticatedUser& user)
{
  const std::string resourceId(request->groups[0]);

  {
    std::unique_ptr<IPermissionContext> context(EducationConfiguration::GetInstance().CreatePermissionContext());

    if (!OrthancDatabase::IsGrantedResource(*context, user, level, resourceId))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_ForbiddenAccess);
    }
  }

  std::string resourcePath;
  std::string lastUpdatePath;

  switch (level)
  {
    case Orthanc::ResourceType_Study:
      resourcePath = "/studies/" + resourceId;
      lastUpdatePath = resourcePath + "/metadata/LastUpdate";
      break;

    case Orthanc::ResourceType_Series:
      resourcePath = "/series/" + resourceId;
      lastUpdatePath = resourcePath + "/metadata/LastUpdate";
      break;

    case Orthanc::ResourceType_Instance:
      resourcePath = "/instances/" + resourceId;
      lastUpdatePath = resourcePath + "/metadata/ReceptionDate";
      break;

    default:
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }

  std::string preview;

  std::string lastUpdate;
  if (OrthancPlugins::RestApiGetString(lastUpdate, lastUpdatePath, false))
  {
    Json::Value metadata;
    if (OrthancPlugins::RestApiGet(metadata, resourcePath + "/metadata/" + METADATA_PREVIEW, false))
    {
      if (lastUpdate == Orthanc::SerializationToolbox::ReadString(metadata, "last-update", ""))
      {
        std::string b64 = Orthanc::SerializationToolbox::ReadString(metadata, "jpeg", "");
        if (!b64.empty())
        {
          Orthanc::Toolbox::DecodeBase64(preview, b64);
          HttpToolbox::AnswerBuffer(output, preview, Orthanc::MimeType_Jpeg);
          return;
        }
      }
    }
  }

  {
    Orthanc::Semaphore::Locker locker(previewThrottler_);

    OrthancPlugins::HttpHeaders headers;
    headers["Accept"] = Orthanc::EnumerationToString(Orthanc::MimeType_Jpeg);

    bool success = false;

    switch (level)
    {
      case Orthanc::ResourceType_Study:
      {
        Json::Value study, series;
        if (OrthancPlugins::RestApiGet(study, resourcePath, false) &&
            OrthancPlugins::RestApiGet(series, "/series/" + study["Series"][0].asString(), false))
        {
          const std::string instance = series["Instances"][0].asString();
          success = OrthancPlugins::RestApiGetString(preview, "/instances/" + instance + "/preview", headers, false);
        }

        break;
      }

      case Orthanc::ResourceType_Series:
      {
        Json::Value series;
        if (OrthancPlugins::RestApiGet(series, resourcePath, false))
        {
          const std::string instance = series["Instances"][0].asString();

          std::string sopClassUid;
          if (EducationConfiguration::GetInstance().HasPluginWholeSlideImaging() &&
              OrthancPlugins::RestApiGetString(sopClassUid, "/instances/" + instance + "/metadata/SopClassUid", false) &&
              Orthanc::Toolbox::StripSpaces(sopClassUid) == "1.2.840.10008.5.1.4.1.1.77.1.6")
          {
            // This is a microscopy image
            static const char* const FIELD_RESOLUTIONS = "Resolutions";

            Json::Value pyramid;
            if (OrthancPlugins::RestApiGet(pyramid, "/wsi/pyramids/" + resourceId, headers, true) &&
                pyramid.isMember(FIELD_RESOLUTIONS))
            {
              const Json::Value& resolutions = pyramid[FIELD_RESOLUTIONS];
              if (resolutions.type() == Json::arrayValue)
              {
                size_t largestIndex = 0;
                double largestValue = resolutions[0].asDouble();
                for (Json::Value::ArrayIndex i = 1; i < resolutions.size(); i++)
                {
                  double value = resolutions[i].asDouble();
                  if (value > largestValue)
                  {
                    largestIndex = i;
                    largestValue = value;
                  }
                }

                success = OrthancPlugins::RestApiGetString(preview, "/wsi/tiles/" + resourceId + "/" +
                                                           boost::lexical_cast<std::string>(largestIndex) + "/0/0", headers, true);
              }
            }
          }

          if (!success)
          {
            success = OrthancPlugins::RestApiGetString(preview, "/instances/" + instance + "/preview", headers, false);
          }
        }

        break;
      }

      case Orthanc::ResourceType_Instance:
        success = OrthancPlugins::RestApiGetString(preview, resourcePath + "/preview", headers, false);
        break;

      default:
        throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }

    if (!success)
    {
      OrthancPlugins::OrthancImage white(OrthancPluginPixelFormat_Grayscale8, 128, 128);
      memset(white.GetBuffer(), 255, white.GetWidth() * white.GetHeight());

      OrthancPlugins::MemoryBuffer jpeg;
      white.CompressJpegImage(jpeg, 70);
      jpeg.ToString(preview);
    }
  }

  std::string b64;
  Orthanc::Toolbox::EncodeBase64(b64, preview);

  Json::Value metadata = Json::objectValue;
  metadata["jpeg"] = b64;
  metadata["last-update"] = lastUpdate;

  Json::Value dummy;
  OrthancPlugins::RestApiPut(dummy, resourcePath + "/metadata/" + METADATA_PREVIEW, metadata.toStyledString(), false);

  HttpToolbox::AnswerBuffer(output, preview, Orthanc::MimeType_Jpeg);
}


static void GetResourceFromBody(Orthanc::ResourceType& level /* out */,
                                std::string& resourceId /* out */,
                                const Json::Value& body)
{
  Json::Value resource;

  if (HttpToolbox::LookupJsonObject(resource, body, "resource"))
  {
    level = Orthanc::StringToResourceType(Orthanc::SerializationToolbox::ReadString(resource, "level").c_str());
    resourceId = Orthanc::SerializationToolbox::ReadString(resource, "resource-id");
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
  }
}


void ChangeImageTitle(OrthancPluginRestOutput* output,
                      const std::string& url,
                      const OrthancPluginHttpRequest* request,
                      const AuthenticatedUser& user,
                      const Json::Value& body)
{
  assert(user.GetRole() == Role_Administrator);

  Orthanc::ResourceType level;
  std::string resourceId;
  GetResourceFromBody(level, resourceId, body);

  const std::string title = Orthanc::SerializationToolbox::ReadString(body, "title");

  std::string path;
  switch (level)
  {
    case Orthanc::ResourceType_Study:
      path = "/studies/";
      break;

    case Orthanc::ResourceType_Series:
      path = "/series/";
      break;

    case Orthanc::ResourceType_Instance:
      path = "/instances/";
      break;

    default:
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }

  path += resourceId + "/metadata/" + METADATA_INFO;

  Json::Value metadata;
  if (!OrthancPlugins::RestApiGet(metadata, path, false) ||
      metadata.type() != Json::objectValue)
  {
    // The metadata has not been created yet
    metadata = Json::objectValue;
  }

  metadata["title"] = title;

  Json::Value dummy;
  if (OrthancPlugins::RestApiPut(metadata, path, metadata, false))
  {
    metadata = Json::objectValue;
    HttpToolbox::AnswerText(output, "");
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
  }
}


void LinkResourceWithProject(OrthancPluginRestOutput* output,
                             const std::string& url,
                             const OrthancPluginHttpRequest* request,
                             const AuthenticatedUser& user,
                             const Json::Value& body)
{
  assert(user.GetRole() == Role_Administrator);

  const std::string data = Orthanc::SerializationToolbox::ReadString(body, "data");
  const std::string label = LABEL_PREFIX + Orthanc::SerializationToolbox::ReadString(body, "project");

  Orthanc::ResourceType level;
  std::string resourceId;

  if (OrthancDatabase::LookupResourceByUserInput(level, resourceId, data))
  {
    std::string path;
    switch (level)
    {
    case Orthanc::ResourceType_Study:
      path = "/studies/" + resourceId;
      break;

    case Orthanc::ResourceType_Series:
      path = "/series/" + resourceId;
      break;

    case Orthanc::ResourceType_Instance:
      path = "/instances/" + resourceId;
      break;

    default:
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }

    Json::Value dummy;
    if (OrthancPlugins::RestApiPut(dummy, path + "/labels/" + label, std::string(), false))
    {
      HttpToolbox::AnswerText(output, "");
    }
    else
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
    }
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
  }
}


void ListImages(OrthancPluginRestOutput* output,
                const std::string& url,
                const OrthancPluginHttpRequest* request,
                const AuthenticatedUser& user,
                const Json::Value& body)
{
  assert(user.GetRole() == Role_Administrator);

  const std::string project = Orthanc::SerializationToolbox::ReadString(body, "project");

  Json::Value answer;

  if (project == "_all-projects")
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
  }
  else if (project == "_no-project")
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
  }
  else
  {
    OrthancDatabase::FindResourcesInProject(answer, project);
  }

  HttpToolbox::AnswerJson(output, answer);
}


void UnlinkResourceFromProject(OrthancPluginRestOutput* output,
                               const std::string& url,
                               const OrthancPluginHttpRequest* request,
                               const AuthenticatedUser& user,
                               const Json::Value& body)
{
  assert(user.GetRole() == Role_Administrator);

  Orthanc::ResourceType level;
  std::string resourceId;
  GetResourceFromBody(level, resourceId, body);

  const std::string projectId = Orthanc::SerializationToolbox::ReadString(body, "project");
  const std::string label = LABEL_PREFIX + projectId;

  std::string path;
  switch (level)
  {
    case Orthanc::ResourceType_Study:
      path = "/studies/" + resourceId + "/labels/" + label;
      break;

    case Orthanc::ResourceType_Series:
      path = "/series/" + resourceId + "/labels/" + label;
      break;

    case Orthanc::ResourceType_Instance:
      path = "/instances/" + resourceId + "/labels/" + label;
      break;

    default:
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }

  if (OrthancPlugins::RestApiDelete(path, false))
  {
    HttpToolbox::AnswerText(output, "");
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
  }
}


void HandleProjectsConfiguration(OrthancPluginRestOutput* output,
                                 const std::string& url,
                                 const OrthancPluginHttpRequest* request,
                                 const AuthenticatedUser& user)
{
  assert(user.GetRole() == Role_Administrator);

  if (request->method == OrthancPluginHttpMethod_Get)
  {
    // List all the projects
    Json::Value projects = Json::arrayValue;

    {
      DocumentOrientedDatabase::Iterator iterator(ProjectPermissionContext::GetProjects());

      while (iterator.Next())
      {
        const Project& project = iterator.GetDocument<Project>();

        Json::Value item;
        item["id"] = iterator.GetKey();
        item["name"] = project.GetName();
        item["description"] = project.GetDescription();
        item["policy"] = EnumerationToString(project.GetPolicy());
        item["primary_viewer"] = EnumerationToString(project.GetPrimaryViewer());
        HttpToolbox::FormatViewers(item["secondary_viewers"], project.GetSecondaryViewers());
        HttpToolbox::CopySetOfStrings(item["instructors"], project.GetInstructors());
        HttpToolbox::CopySetOfStrings(item["learners"], project.GetLearners());

        if (project.HasLtiContextId())
        {
          item["lti_context_id"] = project.GetLtiContextId();
        }

        projects.append(item);
      }
    }

    HttpToolbox::AnswerJson(output, projects);
  }
  else if (request->method == OrthancPluginHttpMethod_Post)
  {
    // Create a project
    Json::Value body;
    if (!Orthanc::Toolbox::ReadJson(body, request->body, request->bodySize))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
    }
    else
    {
      std::unique_ptr<Project> project(new Project);
      project->SetName(Orthanc::SerializationToolbox::ReadString(body, "name"));
      project->SetDescription(Orthanc::SerializationToolbox::ReadString(body, "description"));

      std::set<ViewerType> viewers;
      EducationConfiguration::GetInstance().ListAvailableViewers(viewers);

      if (viewers.empty())
      {
        // No viewer is installed, assume that Stone Web viewer is the default
        project->SetPrimaryViewer(ViewerType_StoneWebViewer);
      }
      else
      {
        project->SetSecondaryViewers(viewers);

        if (viewers.find(ViewerType_StoneWebViewer) != viewers.end())
        {
          // Use Stone Web viewer as the default, as long as it is installed
          project->SetPrimaryViewer(ViewerType_StoneWebViewer);
        }
        else
        {
          // Stone is not installed, chose a random viewer
          project->SetPrimaryViewer(*viewers.begin());
        }
      }

      Json::Value value;
      project->Serialize(value);

      ProjectPermissionContext::GetProjects().StoreWithAutoincrementedKey(project.release());
      HttpToolbox::AnswerText(output, "");
    }
  }
  else
  {
    OrthancPluginSendMethodNotAllowed(OrthancPlugins::GetGlobalContext(), output, "GET,POST");
  }
}


void HandleSingleProject(OrthancPluginRestOutput* output,
                         const std::string& url,
                         const OrthancPluginHttpRequest* request,
                         const AuthenticatedUser& user)
{
  assert(user.GetRole() == Role_Administrator);

  const std::string projectId(request->groups[0]);

  if (request->method == OrthancPluginHttpMethod_Get)
  {
    DocumentOrientedDatabase::Reader reader(ProjectPermissionContext::GetProjects());

    const Project* project = reader.LookupDocument<Project>(projectId);
    if (project == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
    }
    else
    {
      Json::Value answer;
      OrthancDatabase::FormatProjectWithResources(answer, projectId, *project);
      HttpToolbox::AnswerJson(output, answer);
    }
  }
  else if (request->method == OrthancPluginHttpMethod_Delete)
  {
    ProjectPermissionContext::GetProjects().Remove(projectId);
    HttpToolbox::AnswerText(output, "");
  }
  else
  {
    OrthancPluginSendMethodNotAllowed(OrthancPlugins::GetGlobalContext(), output, "GET,DELETE");
  }
}


void SetLtiClientId(OrthancPluginRestOutput* output,
                    const std::string& url,
                    const OrthancPluginHttpRequest* request,
                    const AuthenticatedUser& user)
{
  assert(user.GetRole() == Role_Administrator);

  if (request->method != OrthancPluginHttpMethod_Put)
  {
    OrthancPluginSendMethodNotAllowed(OrthancPlugins::GetGlobalContext(), output, "PUT");
  }
  else
  {
    Json::Value body;
    if (!Orthanc::Toolbox::ReadJson(body, request->body, request->bodySize) ||
        body.type() != Json::stringValue)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
    }
    else
    {
      EducationConfiguration::GetInstance().SetLtiClientId(body.asString());
      HttpToolbox::AnswerText(output, "");
    }
  }
}


void RegisterEducationRestApiRoutes()
{
  /**
   * Safe routes, accessible to any user (even if not logged in)
   **/

  RestApiRouter::RegisterPublicGetRoute<ServeWebApplication>("/education/app/dashboard.html");
  RestApiRouter::RegisterPublicGetRoute<ServeWebApplication>("/education/app/dashboard.js");
  RestApiRouter::RegisterPublicGetRoute<ServeWebApplication>("/education/app/list-projects.html");
  RestApiRouter::RegisterPublicGetRoute<ServeWebApplication>("/education/app/list-projects.js");
  RestApiRouter::RegisterPublicGetRoute<ServeWebApplication>("/education/app/login.js");
  RestApiRouter::RegisterPublicGetRoute<ServeWebApplication>("/education/app/toolbox.js");

  RestApiRouter::RegisterPublicPostRoute<DoLogin>("/education/do-login");
  RestApiRouter::RegisterPublicGetRoute<DoLogout>("/education/do-logout");

  // Those are safe routes, as they only generate a URL
  RestApiRouter::RegisterPublicPostRoute<GenerateListProjectUrl>("/education/api/list-project-url");
  RestApiRouter::RegisterPublicPostRoute<GenerateViewerUrlFromResource>("/education/api/resource-viewer-url");


  /**
   * Routes that necessitate user authentication (even as a guest)
   **/

  RestApiRouter::RegisterAuthenticatedGetRoute<GetUserProjects>("/education/api/user-projects");
  RestApiRouter::RegisterAuthenticatedGetRoute<RedirectRoot>("/");
  RestApiRouter::RegisterAuthenticatedGetRoute<ServeConfiguration>("/education/api/config");
  RestApiRouter::RegisterAuthenticatedGetRoute<ServeLogin>("/education/app/login.html");
  RestApiRouter::RegisterAuthenticatedRoute<ChangeProjectParameter>("/education/api/projects/{}/{}");

  RestApiRouter::RegisterAuthenticatedGetRoute< GeneratePreview<Orthanc::ResourceType_Study> >("/education/api/preview-study/{}");
  RestApiRouter::RegisterAuthenticatedGetRoute< GeneratePreview<Orthanc::ResourceType_Series> >("/education/api/preview-series/{}");
  RestApiRouter::RegisterAuthenticatedGetRoute< GeneratePreview<Orthanc::ResourceType_Instance> >("/education/api/preview-instance/{}");


  /**
   * Routes that necessitate administrator credentials
   **/

  RestApiRouter::RegisterAdministratorPostRoute<ChangeImageTitle>("/education/api/change-title");
  RestApiRouter::RegisterAdministratorPostRoute<LinkResourceWithProject>("/education/api/link");
  RestApiRouter::RegisterAdministratorPostRoute<ListImages>("/education/api/list-images");
  RestApiRouter::RegisterAdministratorPostRoute<UnlinkResourceFromProject>("/education/api/unlink");
  RestApiRouter::RegisterAdministratorRoute<HandleProjectsConfiguration>("/education/api/projects");
  RestApiRouter::RegisterAdministratorRoute<HandleSingleProject>("/education/api/projects/{}");
  RestApiRouter::RegisterAdministratorRoute<SetLtiClientId>("/education/api/config/lti-client-id");
}


AuthenticatedUser* AuthenticateFromEducationCookie(const std::list<HttpToolbox::Cookie>& cookies)
{
  for (std::list<HttpToolbox::Cookie>::const_iterator it = cookies.begin(); it != cookies.end(); ++it)
  {
    if (it->GetKey() == COOKIE_USER_AUTH)
    {
      try
      {
        return AuthenticatedUser::FromJWT(EducationConfiguration::GetInstance().GetLtiContext(), it->GetValue());
      }
      catch (Orthanc::OrthancException&)
      {
      }
    }
  }

  return NULL;
}

