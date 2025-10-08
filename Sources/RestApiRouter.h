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

#include "Permissions/AuthenticatedUser.h"

#include <OrthancPluginCppWrapper.h>


namespace RestApiRouter
{
  typedef void (*AuthenticatedRestCallback) (OrthancPluginRestOutput* output,
                                             const std::string& url,
                                             const OrthancPluginHttpRequest* request,
                                             const AuthenticatedUser& user);

  typedef void (*AuthenticatedGetCallback) (OrthancPluginRestOutput* output,
                                            const std::string& url,
                                            const OrthancPluginHttpRequest* request,
                                            const AuthenticatedUser& user);

  typedef void (*AuthenticatedPostCallback) (OrthancPluginRestOutput* output,
                                             const std::string& url,
                                             const OrthancPluginHttpRequest* request,
                                             const AuthenticatedUser& user,
                                             const Json::Value& body);

  namespace Internals
  {
    template <AuthenticatedGetCallback Callback>
    static inline void AuthenticatedGetCallbackWrapper(OrthancPluginRestOutput* output,
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
        Callback(output, url, request, user);
      }
    }


    template <AuthenticatedPostCallback Callback>
    static inline void AuthenticatedPostCallbackWrapper(OrthancPluginRestOutput* output,
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
        Json::Value body;
        if (!Orthanc::Toolbox::ReadJson(body, request->body, request->bodySize))
        {
          throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
        }
        else
        {
          Callback(output, url, request, user, body);
        }
      }
    }


    template <AuthenticatedRestCallback Callback>
    static inline void PublicRestCallbackWrapper(OrthancPluginRestOutput* output,
                                                 const char* url,
                                                 const OrthancPluginHttpRequest* request)
    {
      std::unique_ptr<AuthenticatedUser> user(AuthenticatedUser::CreateGuest());
      Callback(output, url, request, *user);
    }


    template <AuthenticatedRestCallback Callback>
    static inline void AuthenticatedRestCallbackWrapper(OrthancPluginRestOutput* output,
                                                        const char* url,
                                                        const OrthancPluginHttpRequest* request)
    {
      std::unique_ptr<AuthenticatedUser> user;
      if (request->authenticationPayloadSize == 0)
      {
        user.reset(AuthenticatedUser::CreateGuest());
      }
      else
      {
        user.reset(AuthenticatedUser::FromHttpRequest(request));
      }

      Callback(output, url, request, *user);
    }


    template <AuthenticatedRestCallback Callback>
    static inline void AdministratorRouteWrapper(OrthancPluginRestOutput* output,
                                                 const std::string& url,
                                                 const OrthancPluginHttpRequest* request,
                                                 const AuthenticatedUser& user)
    {
      if (user.GetRole() != Role_Administrator)
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_ForbiddenAccess);
      }
      else
      {
        Callback(output, url, request, user);
      }
    }
  }


  void RegisterRoute(const std::string& uri,
                     AuthorizationStatus status,
                     OrthancPluginRestCallback callback);

  bool LookupRoute(AuthorizationStatus& status,
                   const std::string& uri);


  template <AuthenticatedRestCallback Callback>
  static void RegisterPublicRoute(const std::string& uri)
  {
    RegisterRoute(uri, AuthorizationStatus_GrantedWithoutPayload,
                  OrthancPlugins::Internals::Protect< Internals::PublicRestCallbackWrapper<Callback> >);
  }

  template <AuthenticatedGetCallback Callback>
  static void RegisterPublicGetRoute(const std::string& uri)
  {
    RegisterPublicRoute< Internals::AuthenticatedGetCallbackWrapper<Callback> >(uri);
  }

  template <AuthenticatedPostCallback Callback>
  static void RegisterPublicPostRoute(const std::string& uri)
  {
    RegisterPublicRoute< Internals::AuthenticatedPostCallbackWrapper<Callback> >(uri);
  }


  template <AuthenticatedRestCallback Callback>
  static void RegisterAuthenticatedRoute(const std::string& uri)
  {
    RegisterRoute(uri, AuthorizationStatus_GrantedWithPayload,
                  OrthancPlugins::Internals::Protect< Internals::AuthenticatedRestCallbackWrapper<Callback> >);
  }

  template <AuthenticatedGetCallback Callback>
  static void RegisterAuthenticatedGetRoute(const std::string& uri)
  {
    RegisterAuthenticatedRoute< Internals::AuthenticatedGetCallbackWrapper<Callback> >(uri);
  }

  template <AuthenticatedPostCallback Callback>
  static void RegisterAuthenticatedPostRoute(const std::string& uri)
  {
    RegisterAuthenticatedRoute< Internals::AuthenticatedPostCallbackWrapper<Callback> >(uri);
  }

  template <AuthenticatedRestCallback Callback>
  static void RegisterAdministratorRoute(const std::string& uri)
  {
    RegisterAuthenticatedRoute< Internals::AdministratorRouteWrapper<Callback> >(uri);
  }

  template <AuthenticatedGetCallback Callback>
  static void RegisterAdministratorGetRoute(const std::string& uri)
  {
    RegisterAdministratorRoute< Internals::AuthenticatedGetCallbackWrapper<Callback> >(uri);
  }

  template <AuthenticatedPostCallback Callback>
  static void RegisterAdministratorPostRoute(const std::string& uri)
  {
    RegisterAdministratorRoute< Internals::AuthenticatedPostCallbackWrapper<Callback> >(uri);
  }
}
