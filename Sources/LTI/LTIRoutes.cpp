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


#include "LTIRoutes.h"

#include "../EducationConfiguration.h"
#include "../HttpToolbox.h"
#include "../OrthancDatabase.h"
#include "../ProjectPermissionContext.h"
#include "../RestApiRouter.h"
#include "../Security/PlatformKeysRegistry.h"

#include <OrthancPluginCppWrapper.h>
#include <SerializationToolbox.h>

#include <cassert>


static const char* const COOKIE_LTI = "orthanc-education-lti";

static std::unique_ptr<PlatformKeysRegistry> platformKeysRegistry_;


static void CheckState(const std::map<std::string, std::string>& form,
                       const OrthancPluginHttpRequest* request)
{
  std::string cookieHeader;
  if (!HttpToolbox::LookupCDictionary(cookieHeader, "cookie", true, request->headersCount, request->headersKeys, request->headersValues))
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_Unauthorized);
  }

  const std::string formState = HttpToolbox::ReadMandatoryString(form, "state");

  if (!EducationConfiguration::GetInstance().GetLtiContext().CheckSession(cookieHeader, formState))
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_Unauthorized);
  }
}


static void ServeJwks(OrthancPluginRestOutput* output,
                      const std::string& url,
                      const OrthancPluginHttpRequest* request,
                      const AuthenticatedUser& user)
{
  assert(user.GetRole() == Role_Guest);

  Json::Value key;

  {
    LTIContext::Lock lock(EducationConfiguration::GetInstance().GetLtiContext());
    lock.GetPrivateKey().Export_JWKS_RS256(key, lock.GetKeyId());
  }

  Json::Value keys = Json::arrayValue;
  keys.append(key);

  Json::Value answer = Json::objectValue;
  answer["keys"] = keys;

  HttpToolbox::AnswerJson(output, answer);
}


static bool IsSameUrl(const std::string& a,
                      const std::string& b)
{
  HttpToolbox::CheckUrlScheme(a);
  HttpToolbox::CheckUrlScheme(b);
  return (HttpToolbox::RemoveTrailingSlashes(a) == HttpToolbox::RemoveTrailingSlashes(b));
}


static void ServeOidc(OrthancPluginRestOutput* output,
                      const std::string& url,
                      const OrthancPluginHttpRequest* request,
                      const AuthenticatedUser& user)
{
  assert(user.GetRole() == Role_Guest);

  // This route tests bidirectional communication between Orthanc and Moodle

  if (request->method != OrthancPluginHttpMethod_Post)
  {
    OrthancPluginSendMethodNotAllowed(OrthancPlugins::GetGlobalContext(), output, "POST");
  }
  else
  {
    std::map<std::string, std::string> form;
    HttpToolbox::ParseFormUrlEncoded(form, request->body, request->bodySize);

    const std::string iss = HttpToolbox::ReadMandatoryString(form, "iss");
    const std::string login_hint = HttpToolbox::ReadMandatoryString(form, "login_hint");
    const std::string target_link_uri = HttpToolbox::ReadMandatoryString(form, "target_link_uri");
    const std::string lti_deployment_id = HttpToolbox::ReadMandatoryString(form, "lti_deployment_id");

    const std::string platformUrl = EducationConfiguration::GetInstance().GetLtiPlatformUrl();
    if (!IsSameUrl(iss, platformUrl))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadRequest, "Bad value of \"iss\": \"" + iss +
                                      "\" instead of \"" + platformUrl + "\"");
    }

    std::string cookieHeader;
    if (!HttpToolbox::LookupCDictionary(cookieHeader, "cookie", true, request->headersCount, request->headersKeys, request->headersValues))
    {
      cookieHeader.clear();
    }

    std::string state, nonce;
    EducationConfiguration::GetInstance().GetLtiContext().EnterSession(output, state, nonce, cookieHeader);

    std::map<std::string, std::string> arguments;
    arguments["client_id"] = EducationConfiguration::GetInstance().GetLtiClientId();
    arguments["login_hint"] = login_hint;
    arguments["lti_deployment_id"] = lti_deployment_id;
    arguments["lti_message_hint"] = HttpToolbox::ReadOptionalString(form, "lti_message_hint", "");
    arguments["nonce"] = nonce;
    arguments["prompt"] = "none";
    arguments["redirect_uri"] = target_link_uri;
    arguments["response_mode"] = "form_post";
    arguments["response_type"] = "id_token";
    arguments["scope"] = "openid";
    arguments["state"] = state;

    std::string url;
    HttpToolbox::FormatRedirectionUrl(url, EducationConfiguration::GetInstance().GetLtiPlatformRedirectionUrl(), arguments);

    /*OrthancPluginSetHttpHeader(OrthancPlugins::GetGlobalContext(), output, "Access-Control-Allow-Credentials", "true");
      OrthancPluginSetHttpHeader(OrthancPlugins::GetGlobalContext(), output, "Access-Control-Allow-Origin", platformUrl_.c_str());
      OrthancPluginSetHttpHeader(OrthancPlugins::GetGlobalContext(), output, "Vary", "Origin, Cookie");
      OrthancPluginSetHttpHeader(OrthancPlugins::GetGlobalContext(), output, "Content-Type", "text/html; charset=utf-8");*/

    // We manually reimplement "OrthancPluginRedirect()", otherwise "Set-Cookie" has no effect
    OrthancPluginSetHttpHeader(OrthancPlugins::GetGlobalContext(), output, "Location", url.c_str());
    OrthancPluginSendHttpStatusCode(OrthancPlugins::GetGlobalContext(), output, 302);
  }
}


static void ServeLaunch(OrthancPluginRestOutput* output,
                        const std::string& url,
                        const OrthancPluginHttpRequest* request,
                        const AuthenticatedUser& guestUser)
{
  assert(platformKeysRegistry_.get() != NULL);
  assert(guestUser.GetRole() == Role_Guest);

  if (request->method != OrthancPluginHttpMethod_Post)
  {
    OrthancPluginSendMethodNotAllowed(OrthancPlugins::GetGlobalContext(), output, "POST");
  }
  else
  {
    /**
     * This route does not check that the learner has access to the
     * DICOM resources of interest per se. It only redirects the Web
     * browser to the DICOM viewer. Access will be checked afterward,
     * as the viewer downloads the DICOM resources.
     **/

    std::map<std::string, std::string> form;
    HttpToolbox::ParseFormUrlEncoded(form, request->body, request->bodySize);

    CheckState(form, request);

    JWT jwt(HttpToolbox::ReadMandatoryString(form, "id_token"));
    platformKeysRegistry_->VerifyJWT(jwt, EducationConfiguration::GetInstance().GetLtiPlatformKeysUrl(), 60 /* must be short-lived */);

    std::map<std::string, std::string> custom;
    Orthanc::SerializationToolbox::ReadMapOfStrings(custom, jwt.GetPayload(), "https://purl.imsglobal.org/spec/lti/claim/custom");

    const std::string url = HttpToolbox::ReadMandatoryString(custom, "orthanc_url");

    {
      std::unique_ptr<IPermissionContext> context(EducationConfiguration::GetInstance().CreatePermissionContext());

      std::unique_ptr<AuthenticatedUser> user(AuthenticatedUser::FromLti(*context, jwt.GetPayload()));

      std::string token;
      user->ForgeJWT(token, EducationConfiguration::GetInstance().GetLtiContext(),
                     EducationConfiguration::GetInstance().GetMaxLoginAgeSeconds());

      HttpToolbox::SetCookie(output, COOKIE_LTI, token, CookieSameSite_Lax);
    }

    // We manually reimplement "OrthancPluginRedirect()", to redirect the POST to a GET, and to set JWT cookie
    OrthancPluginSetHttpHeader(OrthancPlugins::GetGlobalContext(), output, "Location", url.c_str());
    OrthancPluginSendHttpStatusCode(OrthancPlugins::GetGlobalContext(), output, 303);  // 303 means "See Other"
  }
}


static void ServeDeep(OrthancPluginRestOutput* output,
                      const std::string& url,
                      const OrthancPluginHttpRequest* request,
                      const AuthenticatedUser& guestUser)
{
  assert(platformKeysRegistry_.get() != NULL);
  assert(guestUser.GetRole() == Role_Guest);

  if (request->method != OrthancPluginHttpMethod_Post)
  {
    OrthancPluginSendMethodNotAllowed(OrthancPlugins::GetGlobalContext(), output, "POST");
  }
  else
  {
    std::map<std::string, std::string> form;
    HttpToolbox::ParseFormUrlEncoded(form, request->body, request->bodySize);

    CheckState(form, request);

    JWT jwt(HttpToolbox::ReadMandatoryString(form, "id_token"));
    platformKeysRegistry_->VerifyJWT(jwt, EducationConfiguration::GetInstance().GetLtiPlatformKeysUrl(), 60 /* must be short-lived */);

    std::unique_ptr<IPermissionContext> context(EducationConfiguration::GetInstance().CreatePermissionContext());
    std::unique_ptr<AuthenticatedUser> user(AuthenticatedUser::FromLti(*context, jwt.GetPayload()));

    std::string orthancEducationJwt;
    user->ForgeJWT(orthancEducationJwt, EducationConfiguration::GetInstance().GetLtiContext(),
                   EducationConfiguration::GetInstance().GetMaxLoginAgeSeconds());

    std::string s;
    HttpToolbox::GetWebApplicationResource(s, "deep.html");

    const Json::Value& payload = jwt.GetPayload();

    Json::Value settings;
    if (!HttpToolbox::LookupJsonObject(settings, payload, "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings"))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol);
    }

    // The info below is copied by "deep.js", then sent to "CreateDeepLink()" or "RedirectToViewer()"

    Json::Value info;
    info["aud"] = Orthanc::SerializationToolbox::ReadString(payload, "iss");
    info["data"] = Orthanc::SerializationToolbox::ReadString(settings, "data", "");
    info["deployment-id"] = Orthanc::SerializationToolbox::ReadString(payload, "https://purl.imsglobal.org/spec/lti/claim/deployment_id");
    info["nonce"] = Orthanc::SerializationToolbox::ReadString(payload, "nonce");
    info["return-url"] = Orthanc::SerializationToolbox::ReadString(settings, "deep_link_return_url");
    info["title"] = Orthanc::SerializationToolbox::ReadString(settings, "title", "This is my title");
    info["orthanc-education-jwt"] = orthancEducationJwt;

    std::string encoded;
    Orthanc::Toolbox::WriteFastJson(encoded, info);

    std::string base64;
    Orthanc::Toolbox::EncodeBase64(base64, encoded);
    boost::replace_all(s, "${INFO}", base64);

    OrthancPluginAnswerBuffer(OrthancPlugins::GetGlobalContext(), output, s.c_str(), s.size(), "text/html");
  }
}


static void ServeDeepJavaScript(OrthancPluginRestOutput* output,
                                const std::string& url,
                                const OrthancPluginHttpRequest* request,
                                const AuthenticatedUser& user)
{
  assert(user.GetRole() == Role_Guest);

  std::string content;
  HttpToolbox::GetWebApplicationResource(content, "deep.js");

  OrthancPluginAnswerBuffer(OrthancPlugins::GetGlobalContext(), output,
                            content.c_str(), content.size(), Orthanc::EnumerationToString(Orthanc::MimeType_JavaScript));
}


static void CheckUserPermission(const std::map<std::string, std::string>& args,
                                const AuthenticatedUser& user)
{
  const std::string levelString = HttpToolbox::ReadMandatoryString(args, "level");
  const Orthanc::ResourceType level = Orthanc::StringToResourceType(levelString.c_str());
  const std::string resourceId = HttpToolbox::ReadMandatoryString(args, "resource-id");

  std::unique_ptr<IPermissionContext> context(EducationConfiguration::GetInstance().CreatePermissionContext());

  if (!OrthancDatabase::IsGrantedResource(*context, user, level, resourceId))
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ForbiddenAccess);
  }
}


static void CreateDeepLink(OrthancPluginRestOutput* output,
                           const std::string& url,
                           const OrthancPluginHttpRequest* request,
                           const AuthenticatedUser& user)
{
  if (request->method != OrthancPluginHttpMethod_Post)
  {
    OrthancPluginSendMethodNotAllowed(OrthancPlugins::GetGlobalContext(), output, "POST");
  }
  else
  {
    std::map<std::string, std::string> args;
    HttpToolbox::ParseFormUrlEncoded(args, request->body, request->bodySize);

    Json::Value link;
    link["type"] = "ltiResourceLink";
    link["url"] = Orthanc::Toolbox::JoinUri(EducationConfiguration::GetInstance().GetLtiOrthancUrl(), "education/lti/launch");

    std::string url;
    const std::string type = HttpToolbox::ReadMandatoryString(args, "link-type");

    if (type == "viewer")
    {
      CheckUserPermission(args, user);

      const ViewerType viewer = ParseViewerType(HttpToolbox::ReadMandatoryString(args, "viewer"));

      link["title"] = HttpToolbox::ReadMandatoryString(args, "title");
      url = Orthanc::Toolbox::JoinUri("../..", OrthancDatabase::GenerateViewerUrl(viewer, args));
    }
    else if (type == "project")
    {
      if (user.GetRole() == Role_Administrator ||
          user.IsInstructorOfProject(user.GetLtiProjectId()))
      {
        link["title"] = "DICOM resources available in this course";
        url = "../app/list-projects.html?open-project-id=" + user.GetLtiProjectId();
      }
      else
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_ForbiddenAccess);
      }
    }
    else
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol);
    }

    // WARNING: LTI does not like dashes "-" in the keys, so we use underscores "_"
    link["custom"]["orthanc_url"] = url;

    Json::Value content = Json::arrayValue;
    content.append(link);

    Json::Value payload;
    payload["aud"] = HttpToolbox::ReadMandatoryString(args, "aud");
    payload["iss"] = EducationConfiguration::GetInstance().GetLtiClientId();
    payload["nonce"] = HttpToolbox::ReadMandatoryString(args, "nonce");

    payload["https://purl.imsglobal.org/spec/lti-dl/claim/content_items"] = content;
    payload["https://purl.imsglobal.org/spec/lti-dl/claim/data"] = HttpToolbox::ReadMandatoryString(args, "data");
    payload["https://purl.imsglobal.org/spec/lti/claim/deployment_id"] = HttpToolbox::ReadMandatoryString(args, "deployment-id");
    payload["https://purl.imsglobal.org/spec/lti/claim/message_type"] = "LtiDeepLinkingResponse";
    payload["https://purl.imsglobal.org/spec/lti/claim/version"] = "1.3.0";

    std::string jwt;
    EducationConfiguration::GetInstance().GetLtiContext().ForgeJWT(jwt, payload, 60 /* expires in 1 minute */);

    OrthancPluginAnswerBuffer(OrthancPlugins::GetGlobalContext(), output, jwt.c_str(), jwt.size(), "application/jwt");
  }
}



static void RedirectToViewer(OrthancPluginRestOutput* output,
                             const std::string& url,
                             const OrthancPluginHttpRequest* request,
                             const AuthenticatedUser& user)
{
  if (request->method != OrthancPluginHttpMethod_Get)
  {
    OrthancPluginSendMethodNotAllowed(OrthancPlugins::GetGlobalContext(), output, "GET");
  }
  else
  {
    std::map<std::string, std::string> args;
    HttpToolbox::ConvertDictionaryFromC(args, false, request->getCount, request->getKeys, request->getValues);

    std::map<std::string, std::string>::const_iterator bearer = args.find("bearer");

    if (bearer != args.end())
    {
      std::unique_ptr<AuthenticatedUser> check(AuthenticatedUser::FromJWT(EducationConfiguration::GetInstance().GetLtiContext(), bearer->second));
      CheckUserPermission(args, *check);

      // Setting the cookie is needed for "RedirectToViewer()" to work, as long as no deep link has been created
      HttpToolbox::SetCookie(output, COOKIE_LTI, bearer->second, CookieSameSite_Lax);
    }
    else
    {
      CheckUserPermission(args, user);
    }

    const ViewerType viewer = ParseViewerType(HttpToolbox::ReadMandatoryString(args, "viewer"));
    const std::string url = Orthanc::Toolbox::JoinUri("../..", OrthancDatabase::GenerateViewerUrl(viewer, args));

    // We manually reimplement "OrthancPluginRedirect()", otherwise "Set-Cookie" has no effect
    OrthancPluginSetHttpHeader(OrthancPlugins::GetGlobalContext(), output, "Location", url.c_str());
    OrthancPluginSendHttpStatusCode(OrthancPlugins::GetGlobalContext(), output, 302);
  }
}


static void ListProjectResourcesForLti(OrthancPluginRestOutput* output,
                                       const std::string& url,
                                       const OrthancPluginHttpRequest* request,
                                       const AuthenticatedUser& user)
{
  if (user.GetRole() == Role_Administrator)
  {
    // LTI authentication can never generate an administrator-level access
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
  }

  const std::string& projectId = user.GetLtiProjectId();

  std::unique_ptr<Project> project(ProjectPermissionContext::GetProjects().CloneDocument<Project>(projectId));
  assert(project.get() != NULL);

  // Is the user an instructor for this project?
  if (ProjectPermissionContext::GetProjectAccessMode(user, projectId, *project) == ProjectAccessMode_Writable)
  {
    Json::Value answer;
    OrthancDatabase::FormatProjectWithResources(answer, projectId, *project);

    HttpToolbox::AnswerJson(output, answer);
  }
  else
  {
    // This route is only available to the instructors of the project
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ForbiddenAccess);
  }
}


static void ServeRegister(OrthancPluginRestOutput* output,
                          const std::string& url,
                          const OrthancPluginHttpRequest* request,
                          const AuthenticatedUser& user)
{
  assert(platformKeysRegistry_.get() != NULL);
  assert(user.GetRole() == Role_Guest);

  // This is "LTI Dynamic Registration Specification"
  // https://www.imsglobal.org/spec/lti-dr/v1p0

  std::map<std::string, std::string> form;
  HttpToolbox::ConvertDictionaryFromC(form, false, request->getCount, request->getKeys, request->getValues);

  const std::string oid_url = HttpToolbox::ReadMandatoryString(form, "openid_configuration");
  const std::string token = HttpToolbox::ReadMandatoryString(form, "registration_token");

  Json::Value platform;

  {
    OrthancPlugins::HttpClient client;
    client.SetTimeout(5);  // 5 seconds to avoid freezing
    client.SetUrl(oid_url);
    OrthancPlugins::HttpHeaders headers;
    client.Execute(headers, platform);
  }

  const std::string issuer = Orthanc::SerializationToolbox::ReadString(platform, "issuer");
  const std::string platformKeysUrl = Orthanc::SerializationToolbox::ReadString(platform, "jwks_uri");
  const std::string platformRedirectionUrl = Orthanc::SerializationToolbox::ReadString(platform, "authorization_endpoint");

  const std::string platformUrl = EducationConfiguration::GetInstance().GetLtiPlatformUrl();
  if (!IsSameUrl(issuer, platformUrl))
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadRequest, "Bad value of \"issuer\": \"" + issuer +
                                    "\" instead of \"" + platformUrl + "\"");
  }

  JWT jwt(token);
  platformKeysRegistry_->VerifyJWT(jwt, platformKeysUrl, 60 /* must be short-lived */);

  const std::string orthancUrl = EducationConfiguration::GetInstance().GetLtiOrthancUrl();

  Json::Value messages = Json::arrayValue;

  {
    Json::Value message;
    message["type"] = "LtiDeepLinkingRequest";
    message["target_link_uri"] = Orthanc::Toolbox::JoinUri(orthancUrl, "education/lti/deep");
    message["label"] = "Add a link to Orthanc";
    message["supported_types"].append("ltiResourceLink");
    messages.append(message);
  }

  Json::Value tool;
  tool["domain"] = EducationConfiguration::GetInstance().GetLtiOrthancDomain();
  tool["target_link_uri"] = Orthanc::Toolbox::JoinUri(orthancUrl, "education/lti/launch");
  tool["claims"].append("iss");
  tool["claims"].append("sub");
  tool["claims"].append("email");  // Strictly speaking, this is not required but it helps debugging
  tool["description"] = "Create links to medical images stored in Orthanc.";
  tool["messages"] = messages;

  Json::Value registration;
  registration["application_type"] = "web";
  registration["grant_types"].append("client_credentials");
  registration["grant_types"].append("implicit");
  registration["response_types"].append("id_token");
  registration["redirect_uris"].append(Orthanc::Toolbox::JoinUri(orthancUrl, "education/lti/launch"));
  registration["redirect_uris"].append(Orthanc::Toolbox::JoinUri(orthancUrl, "education/lti/deep"));
  registration["initiate_login_uri"] = Orthanc::Toolbox::JoinUri(orthancUrl, "education/lti/oidc");
  registration["client_name"] = "Orthanc for Education";
  registration["jwks_uri"] = Orthanc::Toolbox::JoinUri(orthancUrl, "education/lti/jwks");
  registration["logo_uri"] = Orthanc::Toolbox::JoinUri(orthancUrl, "education/static/img/orthanc-h-negative.png");
  registration["token_endpoint_auth_method"] = "private_key_jwt";
  registration["https://purl.imsglobal.org/spec/lti-tool-configuration"] = tool;
  registration["scope"] = "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly";

  Json::Value response;

  {
    OrthancPlugins::HttpClient client;
    client.SetTimeout(5);  // 5 seconds to avoid freezing
    client.SetMethod(OrthancPluginHttpMethod_Post);
    client.SetUrl(Orthanc::SerializationToolbox::ReadString(platform, "registration_endpoint"));
    client.AddHeader("Authorization", "Bearer " + token);
    client.SetBody(registration.toStyledString());
    OrthancPlugins::HttpHeaders headers;
    client.Execute(headers, response);
  }

  EducationConfiguration::GetInstance().SetLtiClientId(Orthanc::SerializationToolbox::ReadString(response, "client_id"));
  EducationConfiguration::GetInstance().SetLtiPlatformKeysUrlFromRegistration(platformKeysUrl);
  EducationConfiguration::GetInstance().SetLtiPlatformRedirectionUrlFromRegistration(platformRedirectionUrl);

  // Check out Step 4:
  // https://www.imsglobal.org/spec/lti-dr/v1p0#step-4-registration-completed-and-activation
  static const std::string close = ("<html><script type=\"text/javascript\">(window.opener || window.parent)."
                                    "postMessage({subject:'org.imsglobal.lti.close'}, '*')</script></html>");
  OrthancPluginAnswerBuffer(OrthancPlugins::GetGlobalContext(), output, close.c_str(), close.size(),
                            Orthanc::EnumerationToString(Orthanc::MimeType_Html));
}


void RegisterLTIRoutes()
{
  if (platformKeysRegistry_.get() != NULL)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }

  LOG(WARNING) << "Enabling LTI 1.3 support";

  platformKeysRegistry_.reset(new PlatformKeysRegistry);
  platformKeysRegistry_->LoadKeys(EducationConfiguration::GetInstance().GetLtiPlatformKeysUrl());

  // Those are safe LTI routes, they can be made public
  RestApiRouter::RegisterPublicGetRoute<ServeDeepJavaScript>("/education/lti/deep.js");
  RestApiRouter::RegisterPublicGetRoute<ServeJwks>("/education/lti/jwks");
  RestApiRouter::RegisterPublicGetRoute<ServeRegister>("/education/lti/register");
  RestApiRouter::RegisterPublicRoute<ServeOidc>("/education/lti/oidc");

  // Those are sensitive routes that must be protected inside the callback
  RestApiRouter::RegisterAuthenticatedRoute<CreateDeepLink>("/education/lti/create-deep-link");
  RestApiRouter::RegisterAuthenticatedRoute<RedirectToViewer>("/education/lti/open-viewer");
  RestApiRouter::RegisterAuthenticatedGetRoute<ListProjectResourcesForLti>("/education/lti/project-resources");

  // Sensitive routes responsible for LTI authentication, they occur
  // after "/education/lti/oidc" and they must be protected using
  // "CheckState()" and "platformKeysRegistry_.VerifyJWT()"
  RestApiRouter::RegisterPublicRoute<ServeDeep>("/education/lti/deep");
  RestApiRouter::RegisterPublicRoute<ServeLaunch>("/education/lti/launch");
}


void ClearLTICookie(OrthancPluginRestOutput* output)
{
  HttpToolbox::ClearCookie(output, COOKIE_LTI, CookieSameSite_Lax);
}


AuthenticatedUser* AuthenticateFromLTICookie(const std::list<HttpToolbox::Cookie>& cookies)
{
  for (std::list<HttpToolbox::Cookie>::const_iterator it = cookies.begin(); it != cookies.end(); ++it)
  {
    if (it->GetKey() == COOKIE_LTI)
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
