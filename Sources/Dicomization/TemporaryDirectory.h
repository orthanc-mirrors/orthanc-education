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


#pragma once

#include <boost/noncopyable.hpp>
#include <boost/filesystem.hpp>


class TemporaryDirectory : public boost::noncopyable
{
private:
  boost::filesystem::path  root_;

public:
  TemporaryDirectory();

  ~TemporaryDirectory();

  const boost::filesystem::path& GetRoot() const
  {
    return root_;
  }

  boost::filesystem::path GetPath(const std::string& filename) const
  {
    return root_ / filename;
  }

  void Clear();

  void WriteFile(const std::string& filename,
                 const std::string& content);
};
