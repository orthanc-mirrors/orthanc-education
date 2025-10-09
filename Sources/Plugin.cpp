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
#include "OrthancDatabase.h"
#include "ProjectPermissionContext.h"
#include "RestApiRouter.h"
#include "EducationConfiguration.h"
#include "LTI/LTIRoutes.h"

#include <EmbeddedResources.h>
#include <SerializationToolbox.h>
#include <SystemToolbox.h>

#include <boost/algorithm/string/predicate.hpp>
#include <cassert>


void ServeStaticAsset(OrthancPluginRestOutput* output,
                      const char* url,
                      const OrthancPluginHttpRequest* request)
{
  if (request->method != OrthancPluginHttpMethod_Get)
  {
    OrthancPluginSendMethodNotAllowed(OrthancPlugins::GetGlobalContext(), output, "GET");
  }
  else
  {
    const std::string filename(request->groups[0]);
    const std::string s = "/" + filename;

    const Orthanc::MimeType mime = Orthanc::SystemToolbox::AutodetectMimeType(filename);

    std::string content;
    Orthanc::EmbeddedResources::GetDirectoryResource(content, Orthanc::EmbeddedResources::STATIC_ASSETS, s.c_str());

    OrthancPluginAnswerBuffer(OrthancPlugins::GetGlobalContext(), output,
                              content.c_str(), content.size(), Orthanc::EnumerationToString(mime));
  }
}


static AuthorizationStatus DoAuthorization(const AuthenticatedUser& user,
                                           const std::string& uri,
                                           const std::map<std::string, std::string>& getArguments)
{
  if (user.GetRole() == Role_Administrator)
  {
    return AuthorizationStatus_GrantedWithPayload;  // Administrators have full access
  }


  /**
   * Check accesses to static resources of Orthanc or of other
   * plugins. In such a situation, it is not necessary to transfer the
   * authentification payload.
   **/

  if (
    // Generic public resources
    uri == "/app/images/favicon.ico" ||
    uri == "/favicon.ico" ||

    // Public resources for the whole-slide imaging viewer
    uri == "/app/libs/jquery.min.js" ||
    uri == "/wsi/app/viewer.html" ||
    uri == "/wsi/app/viewer.js" ||

    // Public resources for the Stone Web viewer
    uri == "/system" ||   // Stone needs access to system information
    boost::starts_with(uri, "/stone-webviewer/") ||

    // Public resources for the whole-slide imaging viewer
    boost::starts_with(uri, "/wsi/app/") ||

    // Public resources for the Kitware VolView plugin
    boost::starts_with(uri, "/volview/") ||

    // Public resources for the OHIF plugin
    boost::starts_with(uri, "/ohif/")
    )
  {
    return AuthorizationStatus_GrantedWithoutPayload;
  }


  /**
   * Check accesses to the native REST API of Orthanc, as well as to
   * the other plugins. In such a situation, it is not necessary to
   * transfer the authentification payload.
   **/

  ProjectPermissionContext::Granter granter(user);

  Orthanc::UriComponents path;
  Orthanc::Toolbox::SplitUriComponents(path, uri);

  if (path.size() == 3 &&
      path[0] == "wsi" &&
      path[1] == "pyramids")
  {
    return (OrthancDatabase::IsGrantedResource(granter, Orthanc::ResourceType_Series, path[2]) ?
            AuthorizationStatus_GrantedWithoutPayload :
            AuthorizationStatus_Forbidden);
  }

  if (path.size() == 6 &&
      path[0] == "wsi" &&
      path[1] == "tiles")
  {
    return (OrthancDatabase::IsGrantedResource(granter, Orthanc::ResourceType_Series, path[2]) ?
            AuthorizationStatus_GrantedWithoutPayload :
            AuthorizationStatus_Forbidden);
  }

  if (path.size() >= 2 &&
      path[0] == "dicom-web")
  {
    return (OrthancDatabase::IsGrantedDicomWeb(granter, path, getArguments) ?
            AuthorizationStatus_GrantedWithoutPayload :
            AuthorizationStatus_Forbidden);
  }

  if (path.size() == 4 &&
      path[0] == "wsi" &&
      path[1] == "frames-pyramids")
  {
    // This is for on-the-fly pyramids
    return (OrthancDatabase::IsGrantedResource(granter, Orthanc::ResourceType_Instance, path[2]) ?
            AuthorizationStatus_GrantedWithoutPayload :
            AuthorizationStatus_Forbidden);
  }

  if (path.size() == 7 &&
      path[0] == "wsi" &&
      path[1] == "frames-tiles")
  {
    // This is for on-the-fly pyramids
    return (OrthancDatabase::IsGrantedResource(granter, Orthanc::ResourceType_Instance, path[2]) ?
            AuthorizationStatus_GrantedWithoutPayload :
            AuthorizationStatus_Forbidden);
  }

  if (path.size() == 3 &&
      path[0] == "studies" &&
      path[2] == "archive")
  {
    // For VolView
    return (OrthancDatabase::IsGrantedResource(granter, Orthanc::ResourceType_Study, path[1]) ?
            AuthorizationStatus_GrantedWithoutPayload :
            AuthorizationStatus_Forbidden);
  }

  if (path.size() == 3 &&
      path[0] == "series" &&
      path[2] == "archive")
  {
    // For VolView
    return (OrthancDatabase::IsGrantedResource(granter, Orthanc::ResourceType_Series, path[1]) ?
            AuthorizationStatus_GrantedWithoutPayload :
            AuthorizationStatus_Forbidden);
  }


  /**
   * Checks related to the education plugin
   **/

  if (path.size() >= 3 &&
      path[0] == "education" &&
      path[1] == "static")
  {
    // Allow access to static resources registered using "OrthancPlugins::RegisterRestCallback()"
    return AuthorizationStatus_GrantedWithoutPayload;
  }
  else
  {
    AuthorizationStatus status;
    if (RestApiRouter::LookupRoute(status, uri))
    {
      return status;
    }
  }

  return AuthorizationStatus_Forbidden;
}



static AuthenticatedUser* DoAuthentication(uint32_t headersCount,
                                           const char* const* headersKeys,
                                           const char* const* headersValues)
{
  /**
   * 1. Check HTTP "Authorization" header for the LTI deep linking
   * user interface (check out "deep.js").
   **/

  std::string header, type, authorization;
  if (HttpToolbox::LookupCDictionary(header, "authorization",  true, headersCount, headersKeys, headersValues) &&
      HttpToolbox::ParseAuthorizationHeader(type, authorization, header) &&
      type == "Bearer")
  {
    try
    {
      return AuthenticatedUser::FromJWT(EducationConfiguration::GetInstance().GetLtiContext(), authorization);
    }
    catch (Orthanc::OrthancException&)
    {
      // Ignore possible errors in the JWT token
    }
  }


  /**
   * 2. Check the custom HTTP header (typically, "Mail") for
   * deployments without LTI
   **/

  std::unique_ptr<AuthenticatedUser> user(EducationConfiguration::GetInstance().DoHttpHeaderAuthentication(
                                            headersCount, headersKeys, headersValues));
  if (user.get() != NULL)
  {
    return user.release();
  }


  /**
   * 3. Check the cookies containing the JWT generated by
   * "/education/do-login" and by "/education/lti/launch"
   **/

  std::string cookieHeader;
  if (HttpToolbox::LookupCDictionary(cookieHeader, "cookie",  true, headersCount, headersKeys, headersValues))
  {
    std::list<HttpToolbox::Cookie> cookies;
    HttpToolbox::ParseCookies(cookies, cookieHeader);

    // Give the priority to the cookie from "/education/do-login"
    user.reset(AuthenticateFromEducationCookie(cookies));
    if (user.get() != NULL)
    {
      return user.release();
    }

    // Fallback to the cookie from LTI if "do-login" was not used
    user.reset(AuthenticateFromLTICookie(cookies));
    if (user.get() != NULL)
    {
      return user.release();
    }
  }


  return AuthenticatedUser::CreateGuest();
}


static OrthancPluginErrorCode HttpAuthentication(
  OrthancPluginHttpAuthenticationStatus*  status,         /* out */
  OrthancPluginMemoryBuffer*              customPayload,  /* out */
  OrthancPluginMemoryBuffer*              redirection,    /* out */
  const char*                             uri,
  const char*                             ip,
  uint32_t                                headersCount,
  const char* const*                      headersKeys,
  const char* const*                      headersValues,
  uint32_t                                getCount,
  const char* const*                      getKeys,
  const char* const*                      getValues)
{
  try
  {
    std::unique_ptr<AuthenticatedUser> user(DoAuthentication(headersCount, headersKeys, headersValues));

    if (user.get() == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }

    *status = OrthancPluginHttpAuthenticationStatus_Forbidden;

    bool redirect = true;

    std::map<std::string, std::string> getArguments;
    HttpToolbox::ConvertDictionaryFromC(getArguments, true /* mandatory for DICOMweb */, getCount, getKeys, getValues);

    AuthorizationStatus authorizationStatus = DoAuthorization(*user, uri, getArguments);
    OrthancPlugins::MemoryBuffer payload;

    switch (authorizationStatus)
    {
    case AuthorizationStatus_GrantedWithPayload:
    case AuthorizationStatus_GrantedWithoutPayload:
      redirect = false;
      *status = OrthancPluginHttpAuthenticationStatus_Granted;
      LOG(INFO) << "Access to " << uri << " is granted to user: " << user->Format();

      if (authorizationStatus == AuthorizationStatus_GrantedWithPayload)
      {
        /**
         * In this case, user information will be available in the REST
         * callbacks by calling "AuthenticatedUser::FromHttpRequest()".
         **/
        user->ToHttpRequest(payload);
      }

      break;

    case AuthorizationStatus_Forbidden:
    {
      std::string args;
      for (uint32_t i = 0; i < getCount; i++)
      {
        const std::string key(getKeys[i]);
        const std::string value(getValues[i]);
        std::string item;
        if (value.empty())
        {
          item = key;
        }
        else
        {
          item = key + "=" + value;
        }
        if (args.empty())
        {
          args = "?" + item;
        }
        else
        {
          args += "&" + item;
        }
      }

      LOG(WARNING) << "Access to " << uri << args << " is denied to user: " << user->Format();
      break;
    }

    default:
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }

    if (redirect)
    {
      std::string target;
      Orthanc::Toolbox::UriEncode(target, uri);

      OrthancPlugins::MemoryBuffer buffer;
      buffer.Assign("/education/app/login.html?target=" + target);

      *status = OrthancPluginHttpAuthenticationStatus_Redirect;
      *redirection = buffer.Release();
    }

    if (payload.GetSize() != 0)
    {
      *customPayload = payload.Release();
    }

    return OrthancPluginErrorCode_Success;
  }
  catch (Orthanc::OrthancException& e)
  {
    LOG(ERROR) << "Error in HTTP authentication callback: " << e.What();
    return OrthancPluginErrorCode_Plugin;
  }
  catch (std::exception& e)
  {
    LOG(ERROR) << "Error in HTTP authentication callback: " << e.what();
    return OrthancPluginErrorCode_Plugin;
  }
  catch (...)
  {
    LOG(ERROR) << "Error in HTTP authentication callback";
    return OrthancPluginErrorCode_Plugin;
  }
}


static OrthancPluginErrorCode OnChangeCallback(OrthancPluginChangeType changeType,
                                               OrthancPluginResourceType resourceType,
                                               const char* resourceId)
{
  try
  {
    switch (changeType)
    {
    case OrthancPluginChangeType_OrthancStarted:
    {
      EducationConfiguration::GetInstance().LoadFromGlobalProperty();

      ProjectPermissionContext::GetProjects().Load();

      {
        Json::Value json;
        OrthancPlugins::RestApiGet(json, "/plugins", false);

        std::set<std::string> plugins;
        Orthanc::SerializationToolbox::ReadSetOfStrings(plugins, json);

        EducationConfiguration::GetInstance().SetPluginOrthancExplorer2(plugins.find("orthanc-explorer-2") != plugins.end());
        EducationConfiguration::GetInstance().SetPluginVolView(plugins.find("volview") != plugins.end());
        EducationConfiguration::GetInstance().SetPluginStoneWebViewer(plugins.find("stone-webviewer") != plugins.end());
        EducationConfiguration::GetInstance().SetPluginWholeSlideImaging(plugins.find("wsi") != plugins.end());
        EducationConfiguration::GetInstance().SetPluginOhif(plugins.find("ohif") != plugins.end());

        std::set<ViewerType> viewers;
        EducationConfiguration::GetInstance().ListAvailableViewers(viewers);

        if (viewers.empty())
        {
          LOG(WARNING) << "No viewer plugin is installed";
        }
      }

      break;
    }

    case OrthancPluginChangeType_OrthancStopped:
      break;

    default:
      break;
    }

    return OrthancPluginErrorCode_Success;
  }
  catch (Orthanc::OrthancException& e)
  {
    LOG(ERROR) << "Error in change callback: " << e.What();
    return OrthancPluginErrorCode_Plugin;
  }
  catch (std::exception& e)
  {
    LOG(ERROR) << "Error in change callback: " << e.what();
    return OrthancPluginErrorCode_Plugin;
  }
  catch (...)
  {
    LOG(ERROR) << "Error in change callback";
    return OrthancPluginErrorCode_Plugin;
  }
}


static bool DisplayPerformanceWarning()
{
  (void) DisplayPerformanceWarning;   // Disable warning about unused function
  LOG(WARNING) << "Performance warning in plugin: "
               << "Non-release build, runtime debug assertions are turned on";
  return true;
}


static void ConfigureAuthentication(Role role,
                                    const OrthancPlugins::OrthancConfiguration& configuration,
                                    const std::string& sectionName)
{
  OrthancPlugins::OrthancConfiguration section(false);
  configuration.GetSection(section, sectionName);

  std::string s;
  if (section.LookupStringValue(s, "Authentication"))
  {
    const AuthenticationMode mode = ParseAuthenticationMode(s);

    switch (role)
    {
    case Role_Administrator:
      EducationConfiguration::GetInstance().SetAdministratorsAuthenticationMode(mode);
      break;

    case Role_Standard:
      EducationConfiguration::GetInstance().SetStandardUsersAuthenticationMode(mode);
      break;

    default:
      throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
    }
  }

  std::map<std::string, std::string> credentials;
  section.GetDictionary(credentials, "Credentials");

  for (std::map<std::string, std::string>::const_iterator it = credentials.begin(); it != credentials.end(); ++it)
  {
    switch (role)
    {
    case Role_Administrator:
      EducationConfiguration::GetInstance().AddAdministratorCredentials(it->first, it->second);
      break;

    case Role_Standard:
      EducationConfiguration::GetInstance().AddStandardUserCredentials(it->first, it->second);
      break;

    default:
      throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
    }
  }

  std::set<std::string> values;
  if (section.LookupSetOfStrings(values, "RestrictedHeaders", false))
  {
    for (std::set<std::string>::const_iterator it = values.begin(); it != values.end(); ++it)
    {
      switch (role)
      {
      case Role_Administrator:
        EducationConfiguration::GetInstance().AddAdministratorRestrictedHttpHeaderValue(*it);
        break;

      case Role_Standard:
        EducationConfiguration::GetInstance().AddStandardUserRestrictedHttpHeaderValue(*it);
        break;

      default:
        throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
      }
    }
  }
}


extern "C"
{
  ORTHANC_PLUGINS_API int32_t OrthancPluginInitialize(OrthancPluginContext* context)
  {
    OrthancPlugins::SetGlobalContext(context, ORTHANC_PLUGIN_NAME);

#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 12, 4)
    Orthanc::Logging::InitializePluginContext(context, ORTHANC_PLUGIN_NAME);
#elif ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 7, 2)
    Orthanc::Logging::InitializePluginContext(context);
#else
    Orthanc::Logging::Initialize(context);
#endif

    assert(DisplayPerformanceWarning());

    Orthanc::Logging::EnableInfoLevel(true);
    Orthanc::Toolbox::InitializeOpenSsl();

    /* Check the version of the Orthanc core */
    if (OrthancPluginCheckVersion(context) == 0)
    {
      char info[1024];
      sprintf(info, "Your version of Orthanc (%s) must be above %d.%d.%d to run this plugin",
              context->orthancVersion,
              ORTHANC_PLUGINS_MINIMAL_MAJOR_NUMBER,
              ORTHANC_PLUGINS_MINIMAL_MINOR_NUMBER,
              ORTHANC_PLUGINS_MINIMAL_REVISION_NUMBER);
      OrthancPluginLogError(context, info);
      return -1;
    }

    OrthancPlugins::SetDescription(ORTHANC_PLUGIN_NAME, "Education plugin for Orthanc.");

    try
    {
      OrthancPluginRegisterHttpAuthentication(context, HttpAuthentication);
      OrthancPluginRegisterOnChangeCallback(context, OnChangeCallback);
      EducationConfiguration::GetInstance().SetPermissionContextFactory(new ProjectPermissionContext::Factory);


      /**
       * Read generic configuration
       **/

      OrthancPlugins::OrthancConfiguration config;

      OrthancPlugins::OrthancConfiguration configEducation(false);
      config.GetSection(configEducation, "Education");

      if (!configEducation.GetBooleanValue("Enabled", false))
      {
        LOG(INFO) << "The education plugin is disabled";
        return 0;
      }
      else
      {
        LOG(WARNING) << "The education plugin is enabled, which overwrites the built-in Orthanc authentication";
      }

      OrthancPlugins::OrthancConfiguration configOE2(false);
      config.GetSection(configOE2, "OrthancExplorer2");

      if (configOE2.GetBooleanValue("Enable", true) &&
          configOE2.GetBooleanValue("IsDefaultOrthancUI", true))
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_IncompatibleConfigurations,
                                        "The education plugin necessitates OrthancExplorer2.IsDefaultOrthancUI to be set to \"false\"");
      }

      std::string s;
      if (configEducation.LookupStringValue(s, "AuthenticationHttpHeader"))
      {
        EducationConfiguration::GetInstance().SetAuthenticationHttpHeader(s);
      }

      unsigned int seconds;
      if (configEducation.LookupUnsignedIntegerValue(seconds, "MaxLoginAge"))
      {
        if (seconds == 0)
        {
          throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
        }
        else
        {
          EducationConfiguration::GetInstance().SetMaxLoginAgeSeconds(seconds);
        }
      }
      else
      {
        EducationConfiguration::GetInstance().SetMaxLoginAgeSeconds(60 * 60 /* defaults to 1 hour */);
      }

      EducationConfiguration::GetInstance().SetListProjectsAsLearner(configEducation.GetBooleanValue("ListProjectsAsLearner", true));

      ConfigureAuthentication(Role_Administrator, configEducation, "Administrators");
      ConfigureAuthentication(Role_Standard, configEducation, "StandardUsers");

      std::list<std::string> values;
      if (configEducation.LookupListOfStrings(values, "PublicRoots", false))
      {
        for (std::list<std::string>::const_iterator it = values.begin(); it != values.end(); ++it)
        {
          EducationConfiguration::GetInstance().AddPublicRoot(*it);
        }
      }


      // Serve the static assets. They cannot be served using
      // "RegisterPublicRoute()", as they might have an arbitrary depth.
      OrthancPlugins::RegisterRestCallback<ServeStaticAsset>("/education/static/(.*)", true);

      RegisterEducationRestApiRoutes();


      /**
       * Read LTI configuration
       **/

      OrthancPlugins::OrthancConfiguration configLti(false);
      configEducation.GetSection(configLti, "LTI");

      if (configLti.GetBooleanValue("Enabled", false))
      {
        EducationConfiguration::GetInstance().SetLtiEnabled(true);

        const std::string orthancUrl = configLti.GetStringValue("OrthancUrl", "");
        if (orthancUrl.empty())
        {
          throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange, "The LTI Orthanc URL is missing from the configuration file");
        }

        EducationConfiguration::GetInstance().SetLtiOrthancUrl(orthancUrl);

        const std::string platformUrl = configLti.GetStringValue("PlatformUrl", "");
        if (platformUrl.empty())
        {
          throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange, "The LTI platform URL is missing from the configuration file");
        }

        EducationConfiguration::GetInstance().SetLtiPlatformUrl(platformUrl);

        std::string s;
        if (configLti.LookupStringValue(s, "PlatformKeysUrl"))
        {
          EducationConfiguration::GetInstance().SetLtiPlatformKeysUrlFromFile(s);
        }

        if (configLti.LookupStringValue(s, "PlatformRedirectionUrl"))
        {
          EducationConfiguration::GetInstance().SetLtiPlatformRedirectionUrlFromFile(s);
        }

        RegisterLTIRoutes();
      }
    }
    catch (Orthanc::OrthancException& e)
    {
      LOG(ERROR) << "Exception while initializing the plugin: " << e.What();
      return -1;
    }

    return 0;
  }


  ORTHANC_PLUGINS_API void OrthancPluginFinalize()
  {
    LOG(WARNING) << "Finalizing the education plugin";
    Orthanc::Toolbox::FinalizeOpenSsl();
    Orthanc::Logging::Finalize();
  }


  ORTHANC_PLUGINS_API const char* OrthancPluginGetName()
  {
    return ORTHANC_PLUGIN_NAME;
  }


  ORTHANC_PLUGINS_API const char* OrthancPluginGetVersion()
  {
    return ORTHANC_PLUGIN_VERSION;
  }
}
