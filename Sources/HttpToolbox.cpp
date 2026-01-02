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


#include "HttpToolbox.h"

#include <OrthancPluginCppWrapper.h>

#include <ChunkedBuffer.h>
#include <OrthancException.h>
#include <SystemToolbox.h>
#include <Toolbox.h>

#if ORTHANC_STANDALONE == 1
#  include <EmbeddedResources.h>
#endif

#include <boost/algorithm/string/predicate.hpp>


namespace HttpToolbox
{
  bool LookupJsonObject(Json::Value& target,
                        const Json::Value& source,
                        const std::string& field)
  {
    if (source.isMember(field) &&
        source[field].type() == Json::objectValue)
    {
      target = source[field];
      return true;
    }
    else
    {
      return false;
    }
  }


  std::string ReadMandatoryString(const std::map<std::string, std::string>& dictionary,
                                  const std::string& field)
  {
    std::map<std::string, std::string>::const_iterator found = dictionary.find(field);
    if (found == dictionary.end())
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadRequest, "Missing field: \"" + field + "\"");
    }
    else
    {
      return found->second;
    }
  }


  std::string ReadOptionalString(const std::map<std::string, std::string>& dictionary,
                                 const std::string& field,
                                 const std::string& defaultValue)
  {
    std::map<std::string, std::string>::const_iterator found = dictionary.find(field);
    if (found == dictionary.end())
    {
      return defaultValue;
    }
    else
    {
      return found->second;
    }
  }


  void EncodeBase64Url(std::string& base64,
                       const std::string& source)
  {
    Orthanc::Toolbox::EncodeBase64(base64, source);

    // https://en.wikipedia.org/wiki/Base64#URL_applications

    for (size_t i = 0; i < base64.size(); i++)
    {
      if (base64[i] == '+')
      {
        base64[i] = '-';
      }
      else if (base64[i] == '/')
      {
        base64[i] = '_';
      }
      else if (base64[i] == '=')   // The end of the base64 has been reached
      {
        base64.resize(i);
        return;
      }
    }
  }


  void DecodeBase64Url(std::string& decoded,
                       const std::string& base64)
  {
    // https://en.wikipedia.org/wiki/Base64#URL_applications

    std::string s;
    s.resize(base64.size());

    for (size_t i = 0; i < base64.size(); i++)
    {
      if (base64[i] == '-')
      {
        s[i] = '+';
      }
      else if (base64[i] == '_')
      {
        s[i] = '/';
      }
      else
      {
        s[i] = base64[i];
      }
    }

    Orthanc::Toolbox::DecodeBase64(decoded, s);
  }


  void ConvertDictionaryFromC(std::map<std::string, std::string>& target,
                              bool toLowerCase,
                              uint32_t count,
                              const char *const *keys,
                              const char *const *values)
  {
    target.clear();

    for (uint32_t i = 0; i < count; i++)
    {
      std::string s;

      if (toLowerCase)
      {
        Orthanc::Toolbox::ToLowerCase(s, keys[i]);
      }
      else
      {
        s = keys[i];
      }

      target[s] = values[i];
    }
  }


  bool LookupCDictionary(std::string& target,
                         const std::string& key,
                         bool toLowerCase,
                         uint32_t count,
                         const char *const *keys,
                         const char *const *values)
  {
    for (uint32_t i = 0; i < count; i++)
    {
      std::string s;

      if (toLowerCase)
      {
        Orthanc::Toolbox::ToLowerCase(s, keys[i]);
      }
      else
      {
        s = keys[i];
      }

      if (s == key)
      {
        target = values[i];
        return true;
      }
    }

    return false;
  }


  bool LookupHttpHeader(std::string& value,
                        const std::map<std::string, std::string>& headers,
                        const std::string& header)
  {
    std::map<std::string, std::string>::const_iterator found = headers.find(header);

    if (found == headers.end())
    {
      return false;
    }
    else
    {
      value = found->second;
      return true;
    }
  }


  bool ParseAuthorizationHeader(std::string& type,
                                std::string& authorization,
                                const std::string& authorizationHeader)
  {
    std::size_t pos = authorizationHeader.find(' ');
    if (pos == std::string::npos)
    {
      return false;
    }
    else
    {
      type = authorizationHeader.substr(0, pos);
      authorization = Orthanc::Toolbox::StripSpaces(authorizationHeader.substr(pos + 1));
      return true;
    }
  }


  bool LookupAuthorizationHeader(std::string& type,
                                 std::string& authorization,
                                 const std::map<std::string, std::string>& headers)
  {
    std::string value;
    if (LookupHttpHeader(value, headers, "authorization"))
    {
      return ParseAuthorizationHeader(type, authorization, value);
    }
    else
    {
      return false;
    }
  }


  void EncodeFormUrl(std::string& target,
                     const std::map<std::string, std::string>& source)
  {
    Orthanc::ChunkedBuffer buffer;
    bool first = true;

    for (std::map<std::string, std::string>::const_iterator it = source.begin(); it != source.end(); ++it)
    {
      if (!it->first.empty())
      {
        if (first)
        {
          first = false;
        }
        else
        {
          buffer.AddChunk("&");
        }

        std::string key;
        Orthanc::Toolbox::UriEncode(key, it->first);
        buffer.AddChunk(key);

        if (!it->second.empty())
        {
          std::string value;
          Orthanc::Toolbox::UriEncode(value, it->second);
          buffer.AddChunk("=");
          buffer.AddChunk(value);
        }
      }
    }

    buffer.Flatten(target);
  }


  void ParseFormUrlEncoded(std::map<std::string, std::string>& target,
                           const void* body,
                           size_t bodySize)
  {
    target.clear();

    std::string decoded;
    decoded.assign(reinterpret_cast<const char*>(body), bodySize);

    std::vector<std::string> parameters;
    Orthanc::Toolbox::TokenizeString(parameters, decoded, '&');

    for (size_t i = 0; i < parameters.size(); i++)
    {
      std::vector<std::string> tokens;
      Orthanc::Toolbox::TokenizeString(tokens, parameters[i], '=');

      if (!tokens.empty())
      {
        std::string& key = tokens[0];
        Orthanc::Toolbox::UrlDecode(key);

        if (tokens.size() == 1)
        {
          target[key] = "";
        }
        else if (tokens.size() == 2)
        {
          std::string& value = tokens[1];
          Orthanc::Toolbox::UrlDecode(value);
          target[key] = value;
        }
      }
    }
  }


  void ParseCookies(std::list<Cookie>& target,
                    const std::string& cookieHeader)
  {
    target.clear();

    std::vector<std::string> cookies;
    Orthanc::Toolbox::TokenizeString(cookies, cookieHeader, ';');

    for (size_t i = 0; i < cookies.size(); i++)
    {
      std::vector<std::string> tokens;
      Orthanc::Toolbox::TokenizeString(tokens, cookies[i], '=');

      if (!tokens.empty())
      {
        std::string key = Orthanc::Toolbox::StripSpaces(tokens[0]);

        if (tokens.size() == 1)
        {
          target.push_back(Cookie(key));
        }
        else if (tokens.size() == 2)
        {
          target.push_back(Cookie(key, Orthanc::Toolbox::StripSpaces(tokens[1])));
        }
      }
    }
  }


  void FormatRedirectionUrl(std::string& target,
                            const std::string& base,
                            const std::map<std::string, std::string>& arguments)
  {
    std::string form;
    EncodeFormUrl(form, arguments);

    if (form.empty())
    {
      target = base;
    }
    else
    {
      target = base + "?" + form;
    }
  }


  void SetCookie(OrthancPluginRestOutput* output,
                 const std::string& cookie,
                 const std::string& value,
                 CookieSameSite sameSite,
                 bool secure)
  {
    std::string s = EnumerationToString(sameSite);

    if (secure)
    {
      s += "; Secure";
    }

    // NB: This is a session cookie, as it does not have "Expires" or "Max-Age"
    std::string setCookie = cookie + "=" + value + "; HttpOnly; SameSite=" + s + "; Path=/";

    OrthancPluginSetHttpHeader(OrthancPlugins::GetGlobalContext(), output, "Set-Cookie", setCookie.c_str());
  }


  void ClearCookie(OrthancPluginRestOutput* output,
                   const std::string& cookie,
                   CookieSameSite sameSite,
                   bool secure)
  {
    std::string s = EnumerationToString(sameSite);

    if (secure)
    {
      s += "; Secure";
    }

    // Deleting the cookie by setting its expiration date in the past
    // https://stackoverflow.com/a/53573622
    std::string setCookie = cookie + "=; HttpOnly; SameSite=" + s + "; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
    OrthancPluginSetHttpHeader(OrthancPlugins::GetGlobalContext(), output, "Set-Cookie", setCookie.c_str());
  }


  void AnswerJson(OrthancPluginRestOutput* output,
                  const Json::Value& value)
  {
    const std::string s = value.toStyledString();
    OrthancPluginAnswerBuffer(OrthancPlugins::GetGlobalContext(), output, s.c_str(), s.size(),
                              Orthanc::EnumerationToString(Orthanc::MimeType_Json));
  }


  void AnswerBuffer(OrthancPluginRestOutput* output,
                    const std::string& value,
                    Orthanc::MimeType type)
  {
    OrthancPluginAnswerBuffer(OrthancPlugins::GetGlobalContext(), output, value.c_str(), value.size(),
                              Orthanc::EnumerationToString(type));
  }


  void GetWebApplicationResource(std::string& target,
                                 const std::string& path)
  {
#if ORTHANC_STANDALONE == 0
    Orthanc::SystemToolbox::ReadFile(target, Orthanc::SystemToolbox::InterpretRelativePath(WEB_APPLICATION_PATH, path));
#else
    const std::string s = "/" + path;
    Orthanc::EmbeddedResources::GetDirectoryResource(target, Orthanc::EmbeddedResources::WEB_APPLICATION, s.c_str());
#endif
  }


  void CheckUrlScheme(const std::string& url)
  {
    if (!boost::starts_with(url, "http://") &&
        !boost::starts_with(url, "https://"))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange, "Not a valid HTTP or HTTPS URL: " + url);
    }
  }


  std::string RemoveTrailingSlashes(const std::string& url)
  {
    size_t slash = url.size();

    while (slash > 0 &&
           url[slash - 1] == '/')
    {
      slash--;
    }

    if (slash == std::string::npos)
    {
      return url;
    }
    else
    {
      return url.substr(0, slash);
    }
  }


  void CopySetOfStrings(Json::Value& target,
                        const std::set<std::string>& source)
  {
    target = Json::arrayValue;
    for (std::set<std::string>::const_iterator it = source.begin(); it != source.end(); ++it)
    {
      target.append(*it);
    }
  }


  void FormatViewers(Json::Value& target,
                     const std::set<ViewerType>& source)
  {
    target = Json::arrayValue;
    for (std::set<ViewerType>::const_iterator it = source.begin(); it != source.end(); ++it)
    {
      Json::Value item;
      item["id"] = EnumerationToString(*it);
      item["description"] = GetViewerDescription(*it);
      target.append(item);
    }
  }
}
