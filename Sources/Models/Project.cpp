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


#include "Project.h"

#include "../HttpToolbox.h"

#include <OrthancException.h>
#include <SerializationToolbox.h>
#include <Toolbox.h>


static void CopyMembers(std::set<std::string>& target,
                        const std::set<std::string>& source)
{
  target.clear();

  for (std::set<std::string>::const_iterator it = source.begin(); it != source.end(); ++it)
  {
    const std::string s = Orthanc::Toolbox::StripSpaces(*it);
    if (!s.empty())
    {
      target.insert(s);
    }
  }
}


static bool IsMember(const std::string& id,
                     const std::set<std::string>& members)
{
  const std::string s = Orthanc::Toolbox::StripSpaces(id);
  return members.find(s) != members.end();
}


static void AddMember(std::set<std::string>& target,
                      const std::string& id)
{
  const std::string s = Orthanc::Toolbox::StripSpaces(id);
  if (s.empty())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }
  else
  {
    target.insert(s);
  }
}


ISerializableDocument* Project::Clone() const
{
  std::unique_ptr<Project> cloned(new Project);
  cloned->content_ = content_;
  return cloned.release();
}


void Project::GetAllViewers(std::set<ViewerType>& target) const
{
  target = content_.secondaryViewers_;
  target.insert(content_.primaryViewer_);
}


bool Project::IsInstructor(const std::string& id) const
{
  return IsMember(id, content_.instructors_);
}


void Project::SetInstructors(const std::set<std::string>& instructors)
{
  CopyMembers(content_.instructors_, instructors);
}


void Project::AddInstructor(const std::string& id)
{
  AddMember(content_.instructors_, id);
}


bool Project::IsLearner(const std::string& id) const
{
  return IsMember(id, content_.learners_);
}


void Project::SetLearners(const std::set<std::string>& learners)
{
  CopyMembers(content_.learners_, learners);
}


void Project::AddLearner(const std::string& id)
{
  AddMember(content_.learners_, id);
}


void Project::ClearLtiContextId()
{
  content_.hasLtiContextId_ = false;
  content_.ltiContextId_.clear();
}


void Project::SetLtiContextId(const std::string& contextId)
{
  content_.hasLtiContextId_ = true;
  content_.ltiContextId_ = contextId;
}


const std::string& Project::GetLtiContextId() const
{
  if (content_.hasLtiContextId_)
  {
    return content_.ltiContextId_;
  }
  else
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }
}

void Project::Serialize(Json::Value& target) const
{
  target = Json::objectValue;
  target["name"] = content_.name_;
  target["description"] = content_.description_;
  target["policy"] = EnumerationToString(content_.policy_);
  target["primary_viewer"] = EnumerationToString(content_.primaryViewer_);

  if (content_.hasLtiContextId_)
  {
    target["lti-context-id"] = content_.ltiContextId_;
  }

  HttpToolbox::CopySetOfStrings(target["instructors"], content_.instructors_);
  HttpToolbox::CopySetOfStrings(target["learners"], content_.learners_);

  Json::Value a = Json::arrayValue;
  for (std::set<ViewerType>::const_iterator it = content_.secondaryViewers_.begin(); it != content_.secondaryViewers_.end(); ++it)
  {
    a.append(EnumerationToString(*it));
  }

  target["secondary_viewers"] = a;
}


ISerializableDocument* Project::Unserializer::Unserialize(const Json::Value& serialized) const
{
  if (serialized.type() != Json::objectValue)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat);
  }

  std::unique_ptr<Project> project(new Project);

  project->SetName(Orthanc::SerializationToolbox::ReadString(serialized, "name"));
  project->SetDescription(Orthanc::SerializationToolbox::ReadString(serialized, "description"));
  project->SetPolicy(ParseProjectPolicy(Orthanc::SerializationToolbox::ReadString(serialized, "policy")));
  project->SetPrimaryViewer(ParseViewerType(Orthanc::SerializationToolbox::ReadString(serialized, "primary_viewer")));

  std::string s = Orthanc::SerializationToolbox::ReadString(serialized, "lti-context-id", "");
  if (!s.empty())
  {
    project->SetLtiContextId(s);
  }

  std::set<std::string> items;
  Orthanc::SerializationToolbox::ReadSetOfStrings(items, serialized, "instructors");
  project->SetInstructors(items);

  Orthanc::SerializationToolbox::ReadSetOfStrings(items, serialized, "learners");
  project->SetLearners(items);

  Orthanc::SerializationToolbox::ReadSetOfStrings(items, serialized, "secondary_viewers");

  std::set<ViewerType> viewers;
  for (std::set<std::string>::const_iterator it = items.begin(); it != items.end(); ++it)
  {
    try
    {
      viewers.insert(ParseViewerType(*it));
    }
    catch (Orthanc::OrthancException&)
    {
      // Ignoring this could be useful for forward compatibility
    }
  }

  project->SetSecondaryViewers(viewers);

  return project.release();
}
