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


#include "TemporaryDirectory.h"

#include <OrthancException.h>
#include <SystemToolbox.h>
#include <TemporaryFile.h>


TemporaryDirectory::TemporaryDirectory()
{
  {
    // Delegate the choice of the path to the Orthanc framework
    Orthanc::TemporaryFile tmp;
    root_ = tmp.GetPath();
  }

  boost::filesystem::create_directories(root_);
}


TemporaryDirectory::~TemporaryDirectory()
{
  try
  {
    Clear();
  }
  catch (...)
  {
    // Ignore errors in destructor
  }
}


void TemporaryDirectory::Clear()
{
  try
  {
    boost::filesystem::remove_all(root_);
  }
  catch (const boost::filesystem::filesystem_error&)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError, "Cannot remove temporary directory: " + root_.string());
  }
}


void TemporaryDirectory::WriteFile(const std::string& filename,
                                   const std::string& content)
{
  boost::filesystem::path path = GetPath(filename);
  boost::filesystem::create_directories(path.parent_path());
  Orthanc::SystemToolbox::WriteFile(content, path.string());
}
