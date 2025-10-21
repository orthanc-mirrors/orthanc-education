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

#include "EducationEnumerations.h"
#include "LTI/LTIContext.h"
#include "Permissions/AuthenticatedUser.h"

#include <boost/noncopyable.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <set>
#include <string>

class EducationConfiguration : public boost::noncopyable
{
private:
  LTIContext             ltiContext_;   // This class is thread-safe

  boost::shared_mutex    mutex_;
  std::string            authenticationHttpHeader_;
  std::list<std::string> publicRoots_;
  unsigned int           maxLoginAge_;  // In seconds
  bool                   listProjectsAsLearner_;
  bool                   secureCookies_;

  bool                   ltiEnabled_;
  std::string            ltiOrthancUrl_;
  std::string            ltiPlatformUrl_;
  std::string            ltiPlatformKeysUrlFromFile_;
  std::string            ltiPlatformKeysUrlFromRegistration_;
  std::string            ltiPlatformRedirectionUrlFromFile_;
  std::string            ltiPlatformRedirectionUrlFromRegistration_;
  std::string            ltiClientId_;

  AuthenticationMode                  administratorsMode_;
  std::map<std::string, std::string>  administratorsCredentials_;
  std::set<std::string>               administratorsHeaders_;

  AuthenticationMode                  standardUsersMode_;
  std::map<std::string, std::string>  standardUsersCredentials_;
  std::set<std::string>               standardUsersHeaders_;

  bool                   hasPluginOrthancExplorer2_;
  bool                   hasPluginStoneWebViewer_;
  bool                   hasPluginVolView_;
  bool                   hasPluginWholeSlideImaging_;
  bool                   hasPluginOhif_;

  unsigned int           sequenceProjectIds_;

  std::string            pathWsiDicomizer_;
  std::string            pathOpenSlide_;

  EducationConfiguration();

  void SaveToGlobalPropertyUnsafe();

public:
  static EducationConfiguration& GetInstance();

  LTIContext& GetLtiContext()
  {
    return ltiContext_;
  }

  void LoadFromGlobalProperty();

  void SetAuthenticationHttpHeader(const std::string& header);

  void AddPublicRoot(const std::string& url);

  bool StartsWithPublicRoot(std::string& path /* out */,
                            const std::string& url);

  bool GetAbsoluteUrl(std::string& target /* out */,
                      const std::string& path);

  void SetMaxLoginAgeSeconds(unsigned int seconds);

  unsigned int GetMaxLoginAgeSeconds();

  void SetListProjectsAsLearner(bool show);

  bool IsListProjectsAsLearner();

  void SetSecureCookies(bool secure);

  bool IsSecureCookies();

  void SetLtiEnabled(bool enabled);

  bool IsLtiEnabled();

  void SetLtiOrthancUrl(const std::string& url);

  std::string GetLtiOrthancUrl();

  std::string GetLtiOrthancDomain();

  void SetLtiPlatformUrl(const std::string& url);

  std::string GetLtiPlatformUrl();

  void SetLtiPlatformKeysUrlFromFile(const std::string& url);

  void SetLtiPlatformKeysUrlFromRegistration(const std::string& url);

  std::string GetLtiPlatformKeysUrl();

  void SetLtiPlatformRedirectionUrlFromFile(const std::string& url);

  void SetLtiPlatformRedirectionUrlFromRegistration(const std::string& url);

  std::string GetLtiPlatformRedirectionUrl();

  void SetLtiClientId(const std::string& id);

  std::string GetLtiClientId();

  void SetAdministratorsAuthenticationMode(AuthenticationMode mode);

  void AddAdministratorCredentials(const std::string& username,
                                   const std::string& password);

  void AddAdministratorRestrictedHttpHeaderValue(const std::string& value);

  void SetStandardUsersAuthenticationMode(AuthenticationMode mode);

  void AddStandardUserCredentials(const std::string& username,
                                  const std::string& password);

  void AddStandardUserRestrictedHttpHeaderValue(const std::string& value);

  bool HasPluginOrthancExplorer2();

  void SetPluginOrthancExplorer2(bool present);

  bool HasPluginStoneWebViewer();

  void SetPluginStoneWebViewer(bool present);

  bool HasPluginVolView();

  void SetPluginVolView(bool present);

  bool HasPluginWholeSlideImaging();

  void SetPluginWholeSlideImaging(bool present);

  bool HasPluginOhif();

  void SetPluginOhif(bool present);

  void ListAvailableViewers(std::set<ViewerType>& target);

  std::string GenerateProjectId();

  void SetPathToWsiDicomizer(const std::string& path);

  std::string GetPathToWsiDicomizer();

  void SetPathToOpenSlide(const std::string& path);

  std::string GetPathToOpenSlide();

  AuthenticatedUser* DoLoginAuthentication(const std::string& username,
                                           const std::string& password);

  AuthenticatedUser* DoHttpHeaderAuthentication(uint32_t headersCount,
                                                const char* const* headersKeys,
                                                const char* const* headersValues);
};
