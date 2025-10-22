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

#include "Dicomization/ActiveUploads.h"
#include "Dicomization/ProcessRunner.h"
#include "Dicomization/TemporaryDirectory.h"
#include "EducationConfiguration.h"
#include "LTI/LTIRoutes.h"
#include "OrthancDatabase.h"
#include "ProjectPermissionContext.h"
#include "RestApiRouter.h"

#include <Images/Image.h>
#include <Images/ImageProcessing.h>
#include <MultiThreading/Semaphore.h>
#include <SerializationToolbox.h>
#include <SystemToolbox.h>
#include <TemporaryFile.h>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/math/special_functions/round.hpp>
#include <boost/regex.hpp>
#include <cassert>


static const char* const COOKIE_USER_AUTH = "orthanc-education-user";


template <bool AdministratorOnly>
void ServeWebApplication(OrthancPluginRestOutput* output,
                         const std::string& url,
                         const OrthancPluginHttpRequest* request,
                         const AuthenticatedUser& user)
{
  if (AdministratorOnly)
  {
    assert(user.GetRole() == Role_Administrator);
  }
  else
  {
    assert(user.GetRole() == Role_Guest);
  }

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

    {
      const bool secureCookies = EducationConfiguration::GetInstance().IsSecureCookies();
      EducationConfiguration::GetInstance().GetLtiContext().CloseSession(output, secureCookies);
      HttpToolbox::SetCookie(output, COOKIE_USER_AUTH, token, CookieSameSite_Lax, secureCookies);
    }

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

  {
    const bool secureCookies = EducationConfiguration::GetInstance().IsSecureCookies();
    EducationConfiguration::GetInstance().GetLtiContext().CloseSession(output, secureCookies);
    HttpToolbox::ClearCookie(output, COOKIE_USER_AUTH, CookieSameSite_Lax, secureCookies);
  }

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

  // NB: "relative_url" is relative to the root of Orthanc
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

  // NB: "relative_url" is relative to the root of Orthanc
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
    config["has_wsi_dicomizer"] = !EducationConfiguration::GetInstance().GetPathToWsiDicomizer().empty();
    config["lti_enabled"] = EducationConfiguration::GetInstance().IsLtiEnabled();
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
    const std::string redirection = Orthanc::Toolbox::JoinUri("../..", GetHomepage(user.GetRole()));
    OrthancPluginRedirect(OrthancPlugins::GetGlobalContext(), output, redirection.c_str());
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
      property != "secondary-viewers")
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




class Thumbnail : public boost::noncopyable
{
private:
  const OrthancPlugins::OrthancImage&      source_;
  std::unique_ptr<Orthanc::ImageAccessor>  modified_;

public:
  explicit Thumbnail(const OrthancPlugins::OrthancImage& source) :
    source_(source)
  {
  }

  Orthanc::PixelFormat GetFormat() const
  {
    if (modified_.get() == NULL)
    {
      switch (source_.GetPixelFormat())
      {
        case OrthancPluginPixelFormat_Grayscale8:
          return Orthanc::PixelFormat_Grayscale8;

        case OrthancPluginPixelFormat_RGB24:
          return Orthanc::PixelFormat_RGB24;

        default:
          throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
      }
    }
    else
    {
      return modified_->GetFormat();
    }
  }

  unsigned int GetWidth() const
  {
    if (modified_.get() == NULL)
    {
      return source_.GetWidth();
    }
    else
    {
      return modified_->GetWidth();
    }
  }

  unsigned int GetHeight() const
  {
    if (modified_.get() == NULL)
    {
      return source_.GetHeight();
    }
    else
    {
      return modified_->GetHeight();
    }
  }

  void GetAccessor(Orthanc::ImageAccessor& accessor) const
  {
    if (modified_.get() == NULL)
    {
      accessor.AssignReadOnly(GetFormat(), source_.GetWidth(), source_.GetHeight(), source_.GetPitch(), source_.GetBuffer());
    }
    else
    {
      modified_->GetReadOnlyAccessor(accessor);
    }
  }

  void Resize(unsigned int width,
              unsigned int height,
              bool smooth)
  {
    Orthanc::ImageAccessor current;
    GetAccessor(current);

    std::unique_ptr<Orthanc::ImageAccessor> resized(new Orthanc::Image(current.GetFormat(), width, height, false));

    if (smooth &&
        width < current.GetWidth() &&
        height < current.GetHeight())  // Only smooth if downscaling
    {
      if (modified_.get() == NULL)
      {
        std::unique_ptr<Orthanc::ImageAccessor> smoothed(Orthanc::Image::Clone(current));
        Orthanc::ImageProcessing::SmoothGaussian5x5(*smoothed, false);
        Orthanc::ImageProcessing::Resize(*resized, *smoothed);
      }
      else
      {
        // The smoothing can be done inplace, as "resized" will overwrite "modified_"
        Orthanc::ImageProcessing::SmoothGaussian5x5(*modified_, false);
        Orthanc::ImageProcessing::Resize(*resized, *modified_);
      }
    }
    else
    {
      Orthanc::ImageProcessing::Resize(*resized, current);
    }

    modified_.reset(resized.release());
  }
};



static const unsigned int THUMBNAIL_WIDTH = 128;
static const unsigned int THUMBNAIL_HEIGHT = 128;


/**
 * NB: "OrthancPlugins::OrthancImage" is used instead of "Orthanc::Image"
 * to avoid linking the education plugin against libjpeg
 **/
static void ResizeThumbnail(OrthancPlugins::OrthancImage& target,
                            const OrthancPlugins::OrthancImage& source)
{
  assert(target.GetWidth() == THUMBNAIL_WIDTH);
  assert(target.GetHeight() == THUMBNAIL_HEIGHT);

  Thumbnail thumbnail(source);

  while (thumbnail.GetWidth() / 2 > target.GetWidth() ||
         thumbnail.GetHeight() / 2 > target.GetHeight())
  {
    // Smooth once we reach the end of the successive resizings
    const bool smooth = (thumbnail.GetWidth() <= 4 * target.GetWidth() &&
                         thumbnail.GetHeight() <= 4 * target.GetHeight());
    thumbnail.Resize(thumbnail.GetWidth() / 2, thumbnail.GetHeight() / 2, smooth);
  }

  const float ratio = std::min(static_cast<float>(target.GetWidth()) / static_cast<float>(thumbnail.GetWidth()),
                               static_cast<float>(target.GetHeight()) / static_cast<float>(thumbnail.GetHeight()));
  thumbnail.Resize(static_cast<unsigned int>(boost::math::llround(static_cast<float>(thumbnail.GetWidth()) * ratio)),
                   static_cast<unsigned int>(boost::math::llround(static_cast<float>(thumbnail.GetHeight()) * ratio)),
                   true /* smooth by default */);

  unsigned int offsetX = (target.GetWidth() - thumbnail.GetWidth()) / 2;
  unsigned int offsetY = (target.GetHeight() - thumbnail.GetHeight()) / 2;

  Orthanc::ImageAccessor targetAccessor;
  targetAccessor.AssignWritable(Orthanc::PixelFormat_RGB24, target.GetWidth(), target.GetHeight(), target.GetPitch(), target.GetBuffer());

  Orthanc::ImageAccessor region;
  targetAccessor.GetRegion(region, offsetX, offsetY, thumbnail.GetWidth(), thumbnail.GetHeight());

  Orthanc::ImageAccessor thumbnailAccessor;
  thumbnail.GetAccessor(thumbnailAccessor);
  Orthanc::ImageProcessing::Convert(region, thumbnailAccessor);
}


template <Orthanc::ResourceType level>
void GeneratePreview(OrthancPluginRestOutput* output,
                     const std::string& url,
                     const OrthancPluginHttpRequest* request,
                     const AuthenticatedUser& user)
{
  const std::string resourceId(request->groups[0]);

  {
    ProjectPermissionContext::Granter granter(user);

    if (!OrthancDatabase::IsGrantedResource(granter, level, resourceId))
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
    static Orthanc::Semaphore previewThrottler_(4);
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

    OrthancPlugins::OrthancImage thumbnail(OrthancPluginPixelFormat_RGB24, THUMBNAIL_WIDTH, THUMBNAIL_HEIGHT);
    memset(thumbnail.GetBuffer(), 255, thumbnail.GetPitch() * thumbnail.GetHeight());

    if (success)
    {
      OrthancPlugins::OrthancImage decoded;
      decoded.UncompressJpegImage(preview.empty() ? NULL : preview.c_str(), preview.size());
      ResizeThumbnail(thumbnail, decoded);
    }

    OrthancPlugins::MemoryBuffer jpeg;
    thumbnail.CompressJpegImage(jpeg, 70);
    jpeg.ToString(preview);
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

  const std::string label = LABEL_PREFIX + Orthanc::SerializationToolbox::ReadString(body, "project");

  Orthanc::ResourceType level;
  std::string resourceId;

  Json::Value resource;
  if (HttpToolbox::LookupJsonObject(resource, body, "resource"))
  {
    resourceId = Orthanc::SerializationToolbox::ReadString(resource, "resource-id");
    level = Orthanc::StringToResourceType(Orthanc::SerializationToolbox::ReadString(resource, "level").c_str());
  }
  else
  {
    const std::string data = Orthanc::SerializationToolbox::ReadString(body, "data");

    if (!OrthancDatabase::LookupResourceByUserInput(level, resourceId, data))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
    }
  }

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


static void CallListUnusedResources(Json::Value& answer,
                                    Orthanc::ResourceType level)
{
  std::set<std::string> allProjectIds;

  {
    DocumentOrientedDatabase::Iterator iterator(ProjectPermissionContext::GetProjects());
    while (iterator.Next())
    {
      allProjectIds.insert(iterator.GetKey());
    }
  }

  switch (level)
  {
    case Orthanc::ResourceType_Study:
      OrthancDatabase::ListUnusedStudies(answer, allProjectIds);
      break;

    case Orthanc::ResourceType_Series:
      OrthancDatabase::ListUnusedSeries(answer, allProjectIds);
      break;

    default:
      throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
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

  if (project == "_all-studies")
  {
    OrthancDatabase::ListAllStudies(answer);
  }
  else if (project == "_unused-studies")
  {
    CallListUnusedResources(answer, Orthanc::ResourceType_Study);
  }
  else if (project == "_unused-series")
  {
    CallListUnusedResources(answer, Orthanc::ResourceType_Series);
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


static void FormatSingleProjectConfiguration(Json::Value& item,
                                             const std::string& projectId,
                                             const Project& project)
{
  item["id"] = projectId;
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
        Json::Value item;
        FormatSingleProjectConfiguration(item, iterator.GetKey(), iterator.GetDocument<Project>());
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

      const std::string key = EducationConfiguration::GetInstance().GenerateProjectId();
      ProjectPermissionContext::GetProjects().Store(key, project.release());

      Json::Value answer;
      answer["id"] = key;
      HttpToolbox::AnswerJson(output, answer);
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
      FormatSingleProjectConfiguration(answer, projectId, *project);
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


void UploadFile(OrthancPluginRestOutput* output,
                const std::string& url,
                const OrthancPluginHttpRequest* request,
                const AuthenticatedUser& user)
{
  assert(user.GetRole() == Role_Administrator);

  if (request->method != OrthancPluginHttpMethod_Post)
  {
    OrthancPluginSendMethodNotAllowed(OrthancPlugins::GetGlobalContext(), output, "POST");
  }
  else
  {
    std::map<std::string, std::string> headers;
    HttpToolbox::ConvertDictionaryFromC(headers, true, request->headersCount, request->headersKeys, request->headersValues);

    std::string uploadId, range;
    if (HttpToolbox::LookupHttpHeader(uploadId, headers, "upload-id") &&
        HttpToolbox::LookupHttpHeader(range, headers, "content-range"))
    {
      boost::regex pattern("bytes ([0-9]+)-([0-9]+)/([0-9]+)");
      boost::smatch what;

      uint64_t start, end, fileSize;
      if (!regex_match(range, what, pattern) ||
          !Orthanc::SerializationToolbox::ParseUnsignedInteger64(start, what[1]) ||
          !Orthanc::SerializationToolbox::ParseUnsignedInteger64(end, what[2]) ||
          !Orthanc::SerializationToolbox::ParseUnsignedInteger64(fileSize, what[3]))
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_BadRequest);
      }
      else
      {
        ActiveUploads::GetInstance().AppendChunk(uploadId, start, end, fileSize, request->body, request->bodySize);
        HttpToolbox::AnswerText(output, "");
      }
    }
    else
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadRequest);
    }
  }
}


class SharedOutputBuffer : public boost::noncopyable
{
private:
  boost::mutex   mutex_;
  std::string    content_;

public:
  void Append(const std::string& data)
  {
    boost::mutex::scoped_lock lock(mutex_);
    content_ += data;
  }

  void GetContent(std::string& content)
  {
    boost::mutex::scoped_lock lock(mutex_);
    content  = content_;
  }
};


class IDicomizer : public boost::noncopyable
{
public:
  virtual ~IDicomizer()
  {
  }

  virtual std::string GetName() = 0;

  virtual std::string GetJobType() = 0;

  virtual bool Execute(std::unique_ptr<Orthanc::TemporaryFile>& upload,
                       SharedOutputBuffer& logs,
                       const bool& stopped) = 0;
};



#include <Compression/ZipReader.h>


static bool IsZipFile(const boost::filesystem::path& path)
{
  std::string header;

#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 12, 10)
  Orthanc::SystemToolbox::ReadFileRange(header, path, 0, 4, false /* don't throw exception */);
#else
  Orthanc::SystemToolbox::ReadFileRange(header, path.string(), 0, 4, false /* don't throw exception */);
#endif

  if (header.size() != 4)
  {
    return false;
  }
  else
  {
    // https://en.wikipedia.org/wiki/List_of_file_signatures
    const uint8_t *b = reinterpret_cast<const uint8_t*>(header.c_str());
    return ((b[0] == 0x50 && b[1] == 0x4b && b[2] == 0x03 && b[3] == 0x04) ||
            (b[0] == 0x50 && b[1] == 0x4b && b[2] == 0x05 && b[3] == 0x06) ||
            (b[0] == 0x50 && b[1] == 0x4b && b[2] == 0x07 && b[3] == 0x08));
  }
}


class WholeSlideImagingDicomizer : public IDicomizer
{
private:
  std::string  studyDescription_;
  uint8_t      backgroundRed_;
  uint8_t      backgroundGreen_;
  uint8_t      backgroundBlue_;
  bool         forceOpenSlide_;
  bool         reconstructPyramid_;

  static bool Unzip(TemporaryDirectory& target,
                    std::string& unzipMaster,
                    const Orthanc::TemporaryFile& zip,
                    const bool& stopped)
  {
    std::unique_ptr<Orthanc::ZipReader> reader(Orthanc::ZipReader::CreateFromFile(zip.GetPath()));

    std::string filename, content;
    while (reader->ReadNextFile(filename, content))
    {
      if (stopped)
      {
        return false;
      }

      // Ignore directories in the ZIP
      if (!boost::ends_with(filename, "/"))
      {
        target.WriteFile(filename, content);

        boost::filesystem::path path(target.GetPath(filename));

        const std::string& extension = path.extension().string();

        if (extension == ".mrxs" ||
            extension == ".ndpi" ||
            extension == ".scn" ||
            extension == ".tif" ||
            extension == ".tiff" ||
            extension == ".png" ||
            extension == ".jpg" ||
            extension == ".jpeg")
        {
          if (unzipMaster.empty())
          {
            unzipMaster = path.string();
          }
          else
          {
            throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "ZIP file containing multiple candidate whole-slide images");
          }
        }
      }
    }

    if (unzipMaster.empty())
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "ZIP file containing no whole-slide image");
    }

    return true;
  }

  void PrepareArguments(std::list<std::string>& args) const
  {
    if (reconstructPyramid_)
    {
      args.push_back("--pyramid");
      args.push_back("1");
    }

    if (forceOpenSlide_)
    {
      args.push_back("--force-openslide");
      args.push_back("1");
    }

    args.push_back("--color");

    {
      char color[32];
      sprintf(color, "%d,%d,%d", backgroundRed_, backgroundGreen_, backgroundBlue_);
      args.push_back(color);
    }

    const std::string openslide = EducationConfiguration::GetInstance().GetPathToOpenSlide();
    if (!openslide.empty())
    {
      args.push_back("--openslide");
      args.push_back(openslide);
    }
  }

  static bool ExecuteDicomizer(const std::string& dicomizer,
                               const std::list<std::string>& args,
                               SharedOutputBuffer& logs,
                               const bool& stopped)
  {
    ProcessRunner runner;
    runner.Start(dicomizer, args, ProcessRunner::Stream_Error);

    while (runner.IsRunning())
    {
      if (stopped)
      {
        runner.Terminate();
        return false;
      }

      std::string s;
      runner.Read(s);
      logs.Append(s);

      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    }

    {
      std::string s;
      runner.Read(s);
      logs.Append(s);
    }

    return (runner.GetExitCode() == 0);
  }

  static bool UploadDicomToOrthanc(const TemporaryDirectory& target,
                                   const bool& stopped)
  {
    boost::filesystem::directory_iterator iterator(target.GetRoot());
    boost::filesystem::directory_iterator end;

    while (iterator != end)
    {
      if (stopped)
      {
        return false;
      }

      std::string content;

#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 12, 10)
      Orthanc::SystemToolbox::ReadFile(content, iterator->path());
#else
      Orthanc::SystemToolbox::ReadFile(content, iterator->path().string());
#endif

      if (!content.empty())
      {
        Json::Value answer;
        if (!OrthancPlugins::RestApiPost(answer, "/instances", content.c_str(), content.size(), false))
        {
          throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError, "Cannot upload a DICOM-ized file");
        }
      }

      ++iterator;
    }

    return true;
  }

public:
  WholeSlideImagingDicomizer() :
    studyDescription_("Whole-slide image"),
    backgroundRed_(255),
    backgroundGreen_(255),
    backgroundBlue_(255),
    forceOpenSlide_(false),
    reconstructPyramid_(true)
  {
  }

  void SetStudyDescription(const std::string& studyDescription)
  {
    studyDescription_ = studyDescription;
  }

  void SetBackgroundColor(uint8_t red,
                          uint8_t green,
                          uint8_t blue)
  {
    backgroundRed_ = red;
    backgroundGreen_ = green;
    backgroundBlue_ = blue;
  }

  void SetForceOpenSlide(bool force)
  {
    forceOpenSlide_ = force;
  }

  void SetReconstructPyramid(bool reconstruct)
  {
    reconstructPyramid_ = reconstruct;
  }

  virtual std::string GetName() ORTHANC_OVERRIDE
  {
    return studyDescription_;
  }

  virtual std::string GetJobType() ORTHANC_OVERRIDE
  {
    return "wsi";
  }

  virtual bool Execute(std::unique_ptr<Orthanc::TemporaryFile>& upload,
                       SharedOutputBuffer& logs,
                       const bool& stopped) ORTHANC_OVERRIDE
  {
    assert(upload.get() != NULL);

    const std::string dicomizer = EducationConfiguration::GetInstance().GetPathToWsiDicomizer();
    if (dicomizer.empty())
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "No DICOM-izer is configured for whole-slide images");
    }

    std::unique_ptr<TemporaryDirectory> unzip;
    std::string unzipMaster;

    if (IsZipFile(upload->GetPath()))
    {
      unzip.reset(new TemporaryDirectory);

      if (!Unzip(*unzip, unzipMaster, *upload, stopped))
      {
        return false;
      }

      // We don't need the ZIP file anymore
      upload.reset(NULL);
    }

    Orthanc::TemporaryFile dataset;

    {
      Json::Value json;
      json["StudyDescription"] = studyDescription_;

      std::string s;
      Orthanc::Toolbox::WriteFastJson(s, json);
      dataset.Write(s);
    }

    std::list<std::string> args;
    PrepareArguments(args);

    args.push_back("--dataset");

#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 12, 10)
    args.push_back(dataset.GetPath().string());
#else
    args.push_back(dataset.GetPath());
#endif

    if (unzip.get() == NULL)
    {
#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 12, 10)
      args.push_back(upload->GetPath().string());
#else
      args.push_back(upload->GetPath());
#endif
    }
    else
    {
      args.push_back(unzipMaster);
    }

    std::unique_ptr<TemporaryDirectory> target(new TemporaryDirectory);
    args.push_back("--folder");
    args.push_back(target->GetRoot().string());

    if (!ExecuteDicomizer(dicomizer, args, logs, stopped))
    {
      return false;
    }

    unzip.reset(NULL);
    upload.reset(NULL);

    return UploadDicomToOrthanc(*target, stopped);
  }
};



#include <JobsEngine/JobsEngine.h>

static Orthanc::JobsEngine engine_(20);  // Only keep 20 completed jobs


class DicomizerJob : public Orthanc::IJob
{
private:
  enum Status
  {
    Status_Running,
    Status_Success,
    Status_Failure
  };

  std::string                  uploadId_;
  std::unique_ptr<IDicomizer>  dicomizer_;
  std::string                  name_;
  std::string                  jobType_;
  SharedOutputBuffer           logs_;
  boost::thread                thread_;
  bool                         stopped_;

  boost::mutex                 mutex_;   // To protect "status_"
  Status                       status_;

  static void Worker(DicomizerJob* that)
  {
    assert(that != NULL);

    std::unique_ptr<Orthanc::TemporaryFile> upload;

    try
    {
      upload.reset(ActiveUploads::GetInstance().ReleaseTemporaryFile(that->uploadId_));
    }
    catch (Orthanc::OrthancException&)
    {
      boost::mutex::scoped_lock lock(that->mutex_);
      that->status_ = Status_Failure;
      return;
    }

    assert(upload.get() != NULL);

    bool success;

    try
    {
      success = that->dicomizer_->Execute(upload, that->logs_, that->stopped_);
    }
    catch (Orthanc::OrthancException& e)
    {
      success = false;
    }
    catch (...)
    {
      success = false;
    }

    {
      boost::mutex::scoped_lock lock(that->mutex_);
      that->status_ = (success ? Status_Success : Status_Failure);
    }
  }

public:
  DicomizerJob(const std::string& uploadId,
               IDicomizer* dicomizer) :
    uploadId_(uploadId),
    dicomizer_(dicomizer),
    stopped_(false),
    status_(Status_Running)
  {
    if (dicomizer == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_NullPointer);
    }

    name_ = dicomizer->GetName();
    jobType_ = dicomizer->GetJobType();
  }

  virtual ~DicomizerJob()
  {
    if (thread_.joinable())
    {
      thread_.join();
    }
  }

  virtual void Start() ORTHANC_OVERRIDE
  {
    thread_ = boost::thread(Worker, this);
  }

  virtual Orthanc::JobStepResult Step(const std::string& jobId) ORTHANC_OVERRIDE
  {
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

    {
      boost::mutex::scoped_lock lock(mutex_);
      if (status_ == Status_Success ||
          status_ == Status_Failure)
      {
        return (status_ == Status_Success ?
                Orthanc::JobStepResult::Success() :
                Orthanc::JobStepResult::Failure(Orthanc::ErrorCode_InternalError, ""));
      }
    }

    return Orthanc::JobStepResult::Continue();
  }

  virtual void Reset() ORTHANC_OVERRIDE
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
  }

  virtual void Stop(Orthanc::JobStopReason reason) ORTHANC_OVERRIDE
  {
    if (reason == Orthanc::JobStopReason_Canceled)
    {
      stopped_ = true;
    }

    if (thread_.joinable())
    {
      thread_.join();
    }
  }

  virtual float GetProgress() const ORTHANC_OVERRIDE
  {
    return 0;
  }

  virtual void GetJobType(std::string& target) const ORTHANC_OVERRIDE
  {
    target = jobType_;
  }

  virtual void GetPublicContent(Json::Value& value) const ORTHANC_OVERRIDE
  {
    std::string logs;
    const_cast<SharedOutputBuffer&>(logs_).GetContent(logs);

    value = Json::objectValue;
    value["logs"] = logs;
    value["name"] = name_;
  }

  virtual bool Serialize(Json::Value& value) const ORTHANC_OVERRIDE
  {
    return false;
  }

  virtual bool GetOutput(std::string& output,
                         Orthanc::MimeType& mime,
                         std::string& filename,
                         const std::string& key) ORTHANC_OVERRIDE
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
  }

  virtual bool DeleteOutput(const std::string& key) ORTHANC_OVERRIDE
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
  }

  virtual void DeleteAllOutputs() ORTHANC_OVERRIDE
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
  }

  virtual bool GetUserData(Json::Value& userData) const ORTHANC_OVERRIDE
  {
    return false;
  }

#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 12, 10)
  virtual void SetUserData(const Json::Value& userData) ORTHANC_OVERRIDE
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
  }
#endif
};



void Dicomization(OrthancPluginRestOutput* output,
                  const std::string& url,
                  const OrthancPluginHttpRequest* request,
                  const AuthenticatedUser& user)
{
  assert(user.GetRole() == Role_Administrator);

  if (request->method == OrthancPluginHttpMethod_Get)
  {
    std::set<std::string> jobs;
    engine_.GetRegistry().ListJobs(jobs);

    Json::Value answer = Json::arrayValue;

    for (std::set<std::string>::const_iterator it = jobs.begin(); it != jobs.end(); ++it)
    {
      Orthanc::JobInfo info;
      if (engine_.GetRegistry().GetJobInfo(info, *it))
      {
        Json::Value item;
        item["id"] = *it;
        item["time"] = boost::posix_time::to_iso_extended_string(info.GetCreationTime());
        item["name"] = Orthanc::SerializationToolbox::ReadString(info.GetStatus().GetPublicContent(), "name");
        item["type"] = info.GetStatus().GetJobType();

        switch (info.GetState())
        {
          case Orthanc::JobState_Success:
            item["status"] = "success";
            break;

          case Orthanc::JobState_Pending:
            item["status"] = "pending";
            break;

          case Orthanc::JobState_Running:
            item["status"] = "running";
            break;

          default:
            item["status"] = "failure";
            break;
        }

        answer.append(item);
      }
    }

    HttpToolbox::AnswerJson(output, answer);
  }
  else if (request->method == OrthancPluginHttpMethod_Post)
  {
    Json::Value body;
    if (!Orthanc::Toolbox::ReadJson(body, request->body, request->bodySize))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
    }
    else
    {
      const std::string uploadId = Orthanc::SerializationToolbox::ReadString(body, "upload-id");

      std::unique_ptr<WholeSlideImagingDicomizer> dicomizer;

      try
      {
        dicomizer.reset(new WholeSlideImagingDicomizer);

        const std::string color = Orthanc::SerializationToolbox::ReadString(body, "background-color");
        if (color == "black")
        {
          dicomizer->SetBackgroundColor(0, 0, 0);
        }
        else if (color == "white")
        {
          dicomizer->SetBackgroundColor(255, 255, 255);
        }
        else
        {
          throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
        }

        dicomizer->SetStudyDescription(Orthanc::SerializationToolbox::ReadString(body, "study-description"));
        dicomizer->SetForceOpenSlide(Orthanc::SerializationToolbox::ReadBoolean(body, "force-openslide"));
        dicomizer->SetReconstructPyramid(Orthanc::SerializationToolbox::ReadBoolean(body, "reconstruct-pyramid"));
      }
      catch (Orthanc::OrthancException&)
      {
        ActiveUploads::GetInstance().Erase(uploadId);
        throw;
      }

      engine_.GetRegistry().Submit(new DicomizerJob(uploadId, dicomizer.release()), 0 /* priority */);

      HttpToolbox::AnswerText(output, "");
    }
  }
  else
  {
    OrthancPluginSendMethodNotAllowed(OrthancPlugins::GetGlobalContext(), output, "GET,POST");
  }
}


void GetDicomizationLogs(OrthancPluginRestOutput* output,
                         const std::string& url,
                         const OrthancPluginHttpRequest* request,
                         const AuthenticatedUser& user)
{
  assert(user.GetRole() == Role_Administrator);

  const std::string jobId(request->groups[0]);

  Orthanc::JobInfo info;
  if (engine_.GetRegistry().GetJobInfo(info, jobId))
  {
    std::string logs = Orthanc::SerializationToolbox::ReadString(info.GetStatus().GetPublicContent(), "logs");
    HttpToolbox::AnswerText(output, logs);
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
  }
}





void RegisterEducationRestApiRoutes()
{
  /**
   * Safe routes, accessible to any user (even if not logged in)
   **/

  RestApiRouter::RegisterPublicGetRoute< ServeWebApplication<false> >("/education/app/list-projects.html");
  RestApiRouter::RegisterPublicGetRoute< ServeWebApplication<false> >("/education/app/list-projects.js");
  RestApiRouter::RegisterPublicGetRoute< ServeWebApplication<false> >("/education/app/login.js");
  RestApiRouter::RegisterPublicGetRoute< ServeWebApplication<false> >("/education/app/toolbox.js");

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

  RestApiRouter::RegisterAdministratorGetRoute< ServeWebApplication<true> >("/education/app/dashboard.html");
  RestApiRouter::RegisterAdministratorGetRoute< ServeWebApplication<true> >("/education/app/dashboard.js");

  RestApiRouter::RegisterAdministratorPostRoute<ChangeImageTitle>("/education/api/change-title");
  RestApiRouter::RegisterAdministratorPostRoute<LinkResourceWithProject>("/education/api/link");
  RestApiRouter::RegisterAdministratorPostRoute<ListImages>("/education/api/list-images");
  RestApiRouter::RegisterAdministratorPostRoute<UnlinkResourceFromProject>("/education/api/unlink");
  RestApiRouter::RegisterAdministratorRoute<HandleProjectsConfiguration>("/education/api/projects");
  RestApiRouter::RegisterAdministratorRoute<HandleSingleProject>("/education/api/projects/{}");
  RestApiRouter::RegisterAdministratorRoute<SetLtiClientId>("/education/api/config/lti-client-id");

  RestApiRouter::RegisterAdministratorRoute<UploadFile>("/education/api/upload");
  RestApiRouter::RegisterAdministratorRoute<Dicomization>("/education/api/dicomization");
  RestApiRouter::RegisterAdministratorGetRoute<GetDicomizationLogs>("/education/api/dicomization/{}/logs");

  engine_.SetWorkersCount(1);
  engine_.Start();
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


void FinalizeEducationJobsEngine()
{
  engine_.Stop();
}
