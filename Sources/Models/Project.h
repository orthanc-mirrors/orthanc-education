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

#include "../EducationEnumerations.h"
#include "IDocumentUnserializer.h"

#include <Compatibility.h>


class Project : public ISerializableDocument
{
private:
  struct Content
  {
    std::string            name_;
    std::string            description_;
    ProjectPolicy          policy_;
    std::set<std::string>  instructors_;
    std::set<std::string>  learners_;
    bool                   hasLtiContextId_;
    std::string            ltiContextId_;
    ViewerType             primaryViewer_;
    std::set<ViewerType>   secondaryViewers_;

    Content() :
      policy_(ProjectPolicy_Hidden),
      hasLtiContextId_(false),
      primaryViewer_(ViewerType_StoneWebViewer)
    {
    }
  };

  Content  content_;

public:
  virtual ISerializableDocument* Clone() const ORTHANC_OVERRIDE;

  void SetName(const std::string& name)
  {
    content_.name_ = name;
  }

  const std::string& GetName() const
  {
    return content_.name_;
  }

  void SetDescription(const std::string& description)
  {
    content_.description_ = description;
  }

  const std::string& GetDescription() const
  {
    return content_.description_;
  }

  void SetPolicy(ProjectPolicy policy)
  {
    content_.policy_ = policy;
  }

  ProjectPolicy GetPolicy() const
  {
    return content_.policy_;
  }

  void SetPrimaryViewer(ViewerType viewer)
  {
    content_.primaryViewer_ = viewer;
  }

  ViewerType GetPrimaryViewer() const
  {
    return content_.primaryViewer_;
  }

  void AddSecondaryViewer(ViewerType viewer)
  {
    content_.secondaryViewers_.insert(viewer);
  }

  void RemoveSecondaryViewer(ViewerType viewer)
  {
    content_.secondaryViewers_.erase(viewer);
  }

  void SetSecondaryViewers(const std::set<ViewerType>& viewers)
  {
    content_.secondaryViewers_ = viewers;
  }

  const std::set<ViewerType>& GetSecondaryViewers() const
  {
    return content_.secondaryViewers_;
  }

  void GetAllViewers(std::set<ViewerType>& target) const;

  bool IsInstructor(const std::string& id) const;

  void SetInstructors(const std::set<std::string>& instructors);

  void AddInstructor(const std::string& id);

  const std::set<std::string>& GetInstructors() const
  {
    return content_.instructors_;
  }

  bool IsLearner(const std::string& id) const;

  void SetLearners(const std::set<std::string>& learners);

  void AddLearner(const std::string& id);

  const std::set<std::string>& GetLearners() const
  {
    return content_.learners_;
  }

  void ClearLtiContextId();

  void SetLtiContextId(const std::string& contextId);

  bool HasLtiContextId() const
  {
    return content_.hasLtiContextId_;
  }

  const std::string& GetLtiContextId() const;

  virtual void Serialize(Json::Value& target) const ORTHANC_OVERRIDE;

  class Unserializer : public IDocumentUnserializer
  {
  public:
    virtual ISerializableDocument* Unserialize(const Json::Value& serialized) const ORTHANC_OVERRIDE;
  };
};
