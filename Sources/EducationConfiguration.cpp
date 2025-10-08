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


#include "EducationConfiguration.h"

#include "HttpToolbox.h"

#include <OrthancException.h>
#include <SerializationToolbox.h>

#include <boost/algorithm/string/predicate.hpp>


static const int32_t GLOBAL_PROPERTY_EDUCATION_SETTINGS = 5000;

static const char* const FIELD_LTI_PLATFORM_KEYS_URL = "lti-platform-keys-url";
static const char* const FIELD_LTI_PLATFORM_REDIRECTION_URL = "lti-platform-redirection-url";
static const char* const FIELD_LTI_CLIENT_ID = "lti-client-id";
static const char* const FIELD_LTI_PRIVATE_KEY = "lti-private-key";
static const char* const FIELD_LTI_PRIVATE_KEY_ID = "lti-private-key-id";


EducationConfiguration::EducationConfiguration() :
  maxLoginAge_(60 * 60 /* by default, 1 hour */),
  listProjectsAsLearner_(true),
  ltiEnabled_(false),
  administratorsMode_(AuthenticationMode_None),
  standardUsersMode_(AuthenticationMode_None),
  hasPluginOrthancExplorer2_(false),
  hasPluginStoneWebViewer_(false),
  hasPluginVolView_(false),
  hasPluginWholeSlideImaging_(false),
  hasPluginOhif_(false)
{
}


EducationConfiguration& EducationConfiguration::GetInstance()
{
  static EducationConfiguration instance;
  return instance;
}


void EducationConfiguration::SaveToGlobalPropertyUnsafe()
{
  Json::Value value;
  value[FIELD_LTI_CLIENT_ID] = ltiClientId_;

  {
    LTIContext::Lock lock(ltiContext_);

    std::string pem;
    lock.GetPrivateKey().SerializePrivate(pem);

    value[FIELD_LTI_PRIVATE_KEY] = pem;
    value[FIELD_LTI_PRIVATE_KEY_ID] = lock.GetKeyId();
  }

  value[FIELD_LTI_PLATFORM_KEYS_URL] = ltiPlatformKeysUrlFromRegistration_;
  value[FIELD_LTI_PLATFORM_REDIRECTION_URL] = ltiPlatformRedirectionUrlFromRegistration_;

  std::string property = value.toStyledString();
  OrthancPluginSetGlobalProperty(OrthancPlugins::GetGlobalContext(), GLOBAL_PROPERTY_EDUCATION_SETTINGS, property.c_str());
}


void EducationConfiguration::LoadFromGlobalProperty()
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);

  OrthancPlugins::OrthancString property;
  property.Assign(OrthancPluginGetGlobalProperty(OrthancPlugins::GetGlobalContext(), GLOBAL_PROPERTY_EDUCATION_SETTINGS, ""));

  bool createKey = true;

  Json::Value config;
  if (!property.IsNullOrEmpty() &&
      OrthancPlugins::ReadJson(config, property.GetContent()))
  {
    ltiClientId_ = Orthanc::SerializationToolbox::ReadString(config, FIELD_LTI_CLIENT_ID, "");

    const std::string pem = Orthanc::SerializationToolbox::ReadString(config, FIELD_LTI_PRIVATE_KEY, "");
    const std::string id = Orthanc::SerializationToolbox::ReadString(config, FIELD_LTI_PRIVATE_KEY_ID, "");

    if (!pem.empty() &&
        !id.empty())
    {
      ltiContext_.LoadPrivateKey(id, pem);
      createKey = false;
    }

    ltiPlatformKeysUrlFromRegistration_ = Orthanc::SerializationToolbox::ReadString(config, FIELD_LTI_PLATFORM_KEYS_URL, "");
    ltiPlatformRedirectionUrlFromRegistration_ = Orthanc::SerializationToolbox::ReadString(config, FIELD_LTI_PLATFORM_REDIRECTION_URL, "");
  }

  if (createKey)
  {
    ltiContext_.CreatePrivateKey();
    SaveToGlobalPropertyUnsafe();
  }
}


void EducationConfiguration::SetAuthenticationHttpHeader(const std::string& header)
{
  if (header.empty())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
  else
  {
    // The Orthanc core converts keys of HTTP headers to lower case
    std::string lower;
    Orthanc::Toolbox::ToLowerCase(lower, header);

    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    authenticationHttpHeader_ = lower;
  }
}


void EducationConfiguration::AddPublicRoot(const std::string& url)
{
  HttpToolbox::CheckUrlScheme(url);

  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    publicRoots_.push_back(HttpToolbox::RemoveTrailingSlashes(url));
  }
}


bool EducationConfiguration::StartsWithPublicRoot(std::string& path /* out */,
                                                  const std::string& url)
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);

  for (std::list<std::string>::const_iterator it = publicRoots_.begin(); it != publicRoots_.end(); ++it)
  {
    if (boost::starts_with(url, *it))
    {
      path = url.substr(it->size());
      return true;
    }
  }

  return false;
}


bool EducationConfiguration::GetAbsoluteUrl(std::string& target /* out */,
                                            const std::string& path)
{
  if (publicRoots_.empty())
  {
    LOG(WARNING) << "No \"PublicRoot\" is available in the configuration file "
                 << "of the education plugin, cannot create an absolute URL";
    return false;
  }
  else
  {
    target = Orthanc::Toolbox::JoinUri(*publicRoots_.begin(), path);
    return true;
  }
}


void EducationConfiguration::SetMaxLoginAgeSeconds(unsigned int seconds)
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);
  maxLoginAge_ = seconds;
}


unsigned int EducationConfiguration::GetMaxLoginAgeSeconds()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);
  return maxLoginAge_;
}


void EducationConfiguration::SetListProjectsAsLearner(bool show)
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);
  listProjectsAsLearner_ = show;
}


bool EducationConfiguration::IsListProjectsAsLearner()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);
  return listProjectsAsLearner_;
}


void EducationConfiguration::SetLtiEnabled(bool enabled)
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);
  ltiEnabled_ = enabled;
}


bool EducationConfiguration::IsLtiEnabled()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);
  return ltiEnabled_;
}


void EducationConfiguration::SetLtiOrthancUrl(const std::string& url)
{
  HttpToolbox::CheckUrlScheme(url);

  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    ltiOrthancUrl_ = HttpToolbox::RemoveTrailingSlashes(url);
  }
}


std::string EducationConfiguration::GetLtiOrthancUrl()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);
  return ltiOrthancUrl_;
}


std::string EducationConfiguration::GetLtiOrthancDomain()
{
  std::vector<std::string> components;

  {
    boost::shared_lock<boost::shared_mutex> lock(mutex_);
    Orthanc::Toolbox::TokenizeString(components, ltiOrthancUrl_, '/');
  }

  if (components.size() < 3 ||
      (components[0] != "http:" &&
       components[0] != "https:") ||
      components[2].empty())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
  else
  {
    return components[2];
  }
}


void EducationConfiguration::SetLtiPlatformUrl(const std::string& url)
{
  HttpToolbox::CheckUrlScheme(url);

  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    ltiPlatformUrl_ = HttpToolbox::RemoveTrailingSlashes(url);
  }
}


std::string EducationConfiguration::GetLtiPlatformUrl()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);
  return ltiPlatformUrl_;
}


void EducationConfiguration::SetLtiPlatformKeysUrlFromFile(const std::string& url)
{
  HttpToolbox::CheckUrlScheme(url);

  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    ltiPlatformKeysUrlFromFile_ = HttpToolbox::RemoveTrailingSlashes(url);
  }
}


void EducationConfiguration::SetLtiPlatformKeysUrlFromRegistration(const std::string& url)
{
  HttpToolbox::CheckUrlScheme(url);

  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    ltiPlatformKeysUrlFromRegistration_ = HttpToolbox::RemoveTrailingSlashes(url);
    SaveToGlobalPropertyUnsafe();
  }
}


std::string EducationConfiguration::GetLtiPlatformKeysUrl()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);

  if (!ltiPlatformKeysUrlFromFile_.empty())
  {
    // The highest priority is the configuration file
    return ltiPlatformKeysUrlFromFile_;
  }
  else if (!ltiPlatformKeysUrlFromRegistration_.empty())
  {
    return ltiPlatformKeysUrlFromRegistration_;
  }
  else
  {
    // The following default URL corresponds to Moodle
    return Orthanc::Toolbox::JoinUri(ltiPlatformUrl_, "/mod/lti/certs.php");
  }
}


void EducationConfiguration::SetLtiPlatformRedirectionUrlFromFile(const std::string& url)
{
  HttpToolbox::CheckUrlScheme(url);

  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    ltiPlatformRedirectionUrlFromFile_ = HttpToolbox::RemoveTrailingSlashes(url);
  }
}


void EducationConfiguration::SetLtiPlatformRedirectionUrlFromRegistration(const std::string& url)
{
  HttpToolbox::CheckUrlScheme(url);

  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    ltiPlatformRedirectionUrlFromRegistration_ = HttpToolbox::RemoveTrailingSlashes(url);
    SaveToGlobalPropertyUnsafe();
  }
}


std::string EducationConfiguration::GetLtiPlatformRedirectionUrl()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);

  if (!ltiPlatformRedirectionUrlFromFile_.empty())
  {
    // The highest priority is the configuration file
    return ltiPlatformRedirectionUrlFromFile_;
  }
  else if (!ltiPlatformRedirectionUrlFromRegistration_.empty())
  {
    return ltiPlatformRedirectionUrlFromRegistration_;
  }
  else
  {
    // The following default URL corresponds to Moodle
    return Orthanc::Toolbox::JoinUri(ltiPlatformUrl_, "/mod/lti/certs.php");
  }
}


void EducationConfiguration::SetLtiClientId(const std::string& id)
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);
  ltiClientId_ = id;
  SaveToGlobalPropertyUnsafe();
}


std::string EducationConfiguration::GetLtiClientId()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);
  return ltiClientId_;
}


void EducationConfiguration::SetPermissionContextFactory(IPermissionContext::IFactory* factory)
{
  if (factory == NULL)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NullPointer);
  }
  else
  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    userPermissionContextFactory_.reset(factory);
  }
}


IPermissionContext* EducationConfiguration::CreatePermissionContext()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);

  if (userPermissionContextFactory_.get() == NULL)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }
  else
  {
    return userPermissionContextFactory_->CreateContext();
  }
}


void EducationConfiguration::SetAdministratorsAuthenticationMode(AuthenticationMode mode)
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);
  administratorsMode_ = mode;
}


void EducationConfiguration::AddAdministratorCredentials(const std::string& username,
                                                              const std::string& password)
{
  if (username.empty() ||
      password.empty())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
  else
  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    administratorsCredentials_[username] = password;
  }
}


void EducationConfiguration::AddAdministratorRestrictedHttpHeaderValue(const std::string& value)
{
  if (value.empty())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
  else
  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    administratorsHeaders_.insert(value);
  }
}


void EducationConfiguration::SetStandardUsersAuthenticationMode(AuthenticationMode mode)
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);
  standardUsersMode_ = mode;
}


void EducationConfiguration::AddStandardUserCredentials(const std::string& username,
                                                        const std::string& password)
{
  if (username.empty() ||
      password.empty())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
  else
  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    standardUsersCredentials_[username] = password;
  }
}


void EducationConfiguration::AddStandardUserRestrictedHttpHeaderValue(const std::string& value)
{
  if (value.empty())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
  else
  {
    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    standardUsersHeaders_.insert(value);
  }
}


static bool CheckLoginAuthentication(const std::map<std::string, std::string>& users,
                                     const std::string& username,
                                     const std::string& password)
{
  std::map<std::string, std::string>::const_iterator found = users.find(username);

  if (found != users.end())
  {
    if (found->second == password)
    {
      return true;
    }
    else
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_Unauthorized);
    }
  }
  else
  {
    return false;
  }
}


bool EducationConfiguration::HasPluginOrthancExplorer2()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);
  return hasPluginOrthancExplorer2_;
}


void EducationConfiguration::SetPluginOrthancExplorer2(bool present)
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);
  hasPluginOrthancExplorer2_ = present;
}


bool EducationConfiguration::HasPluginStoneWebViewer()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);
  return hasPluginStoneWebViewer_;
}


void EducationConfiguration::SetPluginStoneWebViewer(bool present)
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);
  hasPluginStoneWebViewer_ = present;
}


bool EducationConfiguration::HasPluginVolView()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);
  return hasPluginVolView_;
}


void EducationConfiguration::SetPluginVolView(bool present)
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);
  hasPluginVolView_ = present;
}


bool EducationConfiguration::HasPluginWholeSlideImaging()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);
  return hasPluginWholeSlideImaging_;
}


void EducationConfiguration::SetPluginWholeSlideImaging(bool present)
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);
  hasPluginWholeSlideImaging_ = present;
}


bool EducationConfiguration::HasPluginOhif()
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);
  return hasPluginOhif_;
}


void EducationConfiguration::SetPluginOhif(bool present)
{
  boost::unique_lock<boost::shared_mutex> lock(mutex_);
  hasPluginOhif_ = present;
}


void EducationConfiguration::ListAvailableViewers(std::set<ViewerType>& target)
{
  target.clear();

  {
    boost::shared_lock<boost::shared_mutex> lock(mutex_);

    if (hasPluginStoneWebViewer_)
    {
      target.insert(ViewerType_StoneWebViewer);
    }

    if (hasPluginVolView_)
    {
      target.insert(ViewerType_VolView);
    }

    if (hasPluginWholeSlideImaging_)
    {
      target.insert(ViewerType_WholeSlideImaging);
    }

    if (hasPluginOhif_)
    {
      target.insert(ViewerType_OHIF_Basic);
      target.insert(ViewerType_OHIF_VolumeRendering);
      target.insert(ViewerType_OHIF_TumorVolume);
      target.insert(ViewerType_OHIF_Segmentation);
    }
  }
}


AuthenticatedUser* EducationConfiguration::DoLoginAuthentication(const std::string& username,
                                                                 const std::string& password)
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);

  if (administratorsMode_ == AuthenticationMode_Login &&
      CheckLoginAuthentication(administratorsCredentials_, username, password))
  {
    return AuthenticatedUser::CreateAdministrator(username);
  }

  if (standardUsersMode_ == AuthenticationMode_Login &&
      CheckLoginAuthentication(standardUsersCredentials_, username, password))
  {
    std::unique_ptr<IPermissionContext> context(CreatePermissionContext());
    return AuthenticatedUser::CreateStandardUser(*context, username);
  }

  return NULL;
}


static bool IsHttpHeaderAllowed(AuthenticationMode mode,
                                const std::string& value,
                                const std::set<std::string> restrictedValues)
{
  switch (mode)
  {
    case AuthenticationMode_RestrictedHttpHeader:
      return restrictedValues.find(value) != restrictedValues.end();

    case AuthenticationMode_HttpHeader:
      return !value.empty();

    default:
      return false;
  }
}


AuthenticatedUser* EducationConfiguration::DoHttpHeaderAuthentication(uint32_t headersCount,
                                                                      const char* const* headersKeys,
                                                                      const char* const* headersValues)
{
  boost::shared_lock<boost::shared_mutex> lock(mutex_);

  std::string value;

  if (!authenticationHttpHeader_.empty() &&
      HttpToolbox::LookupCDictionary(value, authenticationHttpHeader_, false /* no lowercase */,
                                     headersCount, headersKeys, headersValues))
  {
    if (IsHttpHeaderAllowed(administratorsMode_, value, administratorsHeaders_))
    {
      return AuthenticatedUser::CreateAdministrator(value);
    }

    if (IsHttpHeaderAllowed(standardUsersMode_, value, standardUsersHeaders_))
    {
      std::unique_ptr<IPermissionContext> context(CreatePermissionContext());
      return AuthenticatedUser::CreateStandardUser(*context, value);
    }
  }

  return NULL;
}
