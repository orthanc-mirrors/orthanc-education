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

#include <Enumerations.h>

#include <orthanc/OrthancCPlugin.h>

#include <json/value.h>
#include <list>
#include <map>
#include <string>


namespace HttpToolbox
{
  class Cookie
  {
  private:
    std::string key_;
    std::string value_;

  public:
    explicit Cookie(const std::string& key) :
      key_(key)
    {
    }

    Cookie(const std::string& key,
           const std::string& value) :
      key_(key),
      value_(value)
    {
    }

    const std::string& GetKey() const
    {
      return key_;
    }

    const std::string& GetValue() const
    {
      return value_;
    }
  };

  bool LookupJsonObject(Json::Value& target,
                        const Json::Value& source,
                        const std::string& field);

  std::string ReadMandatoryString(const std::map<std::string, std::string>& dictionary,
                                  const std::string& field);

  std::string ReadOptionalString(const std::map<std::string, std::string>& dictionary,
                                 const std::string& field,
                                 const std::string& defaultValue);

  void EncodeBase64Url(std::string& base64,
                       const std::string& source);

  void DecodeBase64Url(std::string& decoded,
                       const std::string& base64);

  void ConvertDictionaryFromC(std::map<std::string, std::string>& target,
                              bool toLowerCase,
                              uint32_t count,
                              const char *const *keys,
                              const char *const *values);

  bool LookupCDictionary(std::string& target,
                         const std::string& key,
                         bool toLowerCase,
                         uint32_t count,
                         const char *const *keys,
                         const char *const *values);

  bool LookupHttpHeader(std::string& value,
                        const std::map<std::string, std::string>& headers,
                        const std::string& header);

  bool ParseAuthorizationHeader(std::string& type,
                                std::string& authorization,
                                const std::string& authorizationHeader);

  bool LookupAuthorizationHeader(std::string& type,
                                 std::string& authorization,
                                 const std::map<std::string, std::string>& headers);

  void EncodeFormUrl(std::string& target,
                     const std::map<std::string, std::string>& source);

  void ParseFormUrlEncoded(std::map<std::string, std::string>& target,
                           const void* body,
                           size_t bodySize);

  void ParseCookies(std::list<Cookie>& target,
                    const std::string& cookieHeader);

  void FormatRedirectionUrl(std::string& target,
                            const std::string& base,
                            const std::map<std::string, std::string>& arguments);

  void SetCookie(OrthancPluginRestOutput* output,
                 const std::string& cookie,
                 const std::string& value,
                 CookieSameSite sameSite,
                 bool secure);

  void ClearCookie(OrthancPluginRestOutput* output,
                   const std::string& cookie,
                   CookieSameSite sameSite,
                   bool secure);

  void AnswerJson(OrthancPluginRestOutput* output,
                  const Json::Value& value);

  void AnswerBuffer(OrthancPluginRestOutput* output,
                    const std::string& value,
                    Orthanc::MimeType type);

  inline void AnswerText(OrthancPluginRestOutput* output,
                         const std::string& value)
  {
    AnswerBuffer(output, value, Orthanc::MimeType_PlainText);
  }

  void GetWebApplicationResource(std::string& target,
                                 const std::string& path);

  void CheckUrlScheme(const std::string& url);

  std::string RemoveTrailingSlashes(const std::string& url);

  void CopySetOfStrings(Json::Value& target,
                        const std::set<std::string>& source);

  void FormatViewers(Json::Value& target,
                     const std::set<ViewerType>& source);
}
