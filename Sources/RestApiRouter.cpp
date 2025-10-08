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


#include "RestApiRouter.h"

#include <boost/thread.hpp>
#include <cassert>


namespace
{
  class Route : public boost::noncopyable
  {
  private:
    typedef std::map<std::string, Route*>  Children;

    AuthorizationStatus  status_;
    Children             children_;
    Route*               universal_;

  public:
    Route() :
      status_(AuthorizationStatus_Forbidden),
      universal_(NULL)
    {
    }

    ~Route()
    {
      for (Children::iterator it = children_.begin(); it != children_.end(); ++it)
      {
        assert(it->second != NULL);
        delete it->second;
      }

      if (universal_ != NULL)
      {
        delete universal_;
      }
    }

    AuthorizationStatus Classify(const std::vector<std::string>& path,
                                 size_t index) const
    {
      if (index > path.size())
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
      }
      else if (index == path.size())
      {
        return status_;
      }
      else if (universal_ != NULL)
      {
        assert(children_.empty());
        return universal_->Classify(path, index + 1);
      }
      else
      {
        Children::const_iterator found = children_.find(path[index]);
        if (found == children_.end())
        {
          return AuthorizationStatus_Forbidden;
        }
        else
        {
          assert(found->second != NULL);
          return found->second->Classify(path, index + 1);
        }
      }
    }

    void Register(AuthorizationStatus status,
                  const std::vector<std::string>& path,
                  size_t index)
    {
      if (status == AuthorizationStatus_Forbidden ||
          index > path.size())
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
      }
      else if (index == path.size())
      {
        if (status_ == AuthorizationStatus_Forbidden)
        {
          status_ = status;
        }
        else
        {
          // Cannot register twice the same target
          throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
        }
      }
      else if (path[index].empty())
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
      }
      else if (path[index] == "{}")
      {
        if (!children_.empty())
        {
          // Cannot combine a universal target with named target
          throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
        }
        else
        {
          if (universal_ == NULL)
          {
            universal_ = new Route;
          }

          universal_->Register(status, path, index + 1);
        }
      }
      else
      {
        if (universal_ != NULL)
        {
          // Cannot combine a universal target with named target
          throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
        }
        else
        {
          Children::iterator found = children_.find(path[index]);
          if (found == children_.end())
          {
            std::unique_ptr<Route> child(new Route);
            child->Register(status, path, index + 1);
            children_[path[index]] = child.release();
          }
          else
          {
            assert(found->second != NULL);
            found->second->Register(status, path, index + 1);
          }
        }
      }
    }
  };
}


static std::unique_ptr<Route>  root_(new Route);
static boost::shared_mutex     authorizationRoutesMutex_;


namespace RestApiRouter
{
  void RegisterRoute(const std::string& uri,
                     AuthorizationStatus status,
                     OrthancPluginRestCallback callback)
  {
    boost::unique_lock<boost::shared_mutex> lock(authorizationRoutesMutex_);

    std::vector<std::string> path;
    Orthanc::Toolbox::SplitUriComponents(path, uri);
    root_->Register(status, path, 0);

    std::string regex = "/";

    {
      for (size_t i = 0; i < path.size(); i++)
      {
        if (i > 0)
        {
          regex += "/";
        }

        if (path[i] == "{}")
        {
          regex += "([0-9a-zA-Z._-]+)";
        }
        else
        {
          for (size_t j = 0; j < path[i].size(); j++)
          {
            if ((path[i][j] >= '0' && path[i][j] <= '9') ||
                (path[i][j] >= 'a' && path[i][j] <= 'z') ||
                (path[i][j] >= 'A' && path[i][j] <= 'Z') ||
                path[i][j] == '_' ||
                path[i][j] == '-')
            {
              regex += path[i][j];
            }
            else if (path[i][j] == '.')
            {
              regex += "\\.";
            }
            else
            {
              throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange,
                                              "Character \"" + std::string(1, path[i][j]) + "\" not allowed in route: " + uri);
            }
          }
        }
      }
    }

    // "NoLock" because all education callbacks are thread-safe
    OrthancPluginRegisterRestCallbackNoLock(OrthancPlugins::GetGlobalContext(), regex.c_str(), callback);
  }


  bool LookupRoute(AuthorizationStatus& status,
                   const std::string& uri)
  {
    std::vector<std::string> path;
    Orthanc::Toolbox::SplitUriComponents(path, uri);

    {
      boost::shared_lock<boost::shared_mutex>  lock(authorizationRoutesMutex_);

      status = root_->Classify(path, 0);
      return (status != AuthorizationStatus_Forbidden);
    }
  }
}
