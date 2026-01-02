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

#include "IDicomizer.h"
#include "TemporaryDirectory.h"

#include <list>


class WholeSlideImagingDicomizer : public IDicomizer
{
private:
  std::string  studyDescription_;
  uint8_t      backgroundRed_;
  uint8_t      backgroundGreen_;
  uint8_t      backgroundBlue_;
  bool         forceOpenSlide_;
  bool         reconstructPyramid_;

  // New in release 1.1
  bool         imagedVolumeAutodetect_;
  float        imagedVolumeWidth_;

  static bool Unzip(TemporaryDirectory& target,
                    std::string& unzipMaster,
                    const Orthanc::TemporaryFile& zip,
                    const bool& stopped);

  void PrepareArguments(std::list<std::string>& args) const;

  static bool ExecuteDicomizer(const std::string& dicomizer,
                               const std::list<std::string>& args,
                               SharedLogs& logs,
                               const bool& stopped);

  static bool UploadDicomToOrthanc(const TemporaryDirectory& target,
                                   const bool& stopped);

public:
  WholeSlideImagingDicomizer();

  void SetStudyDescription(const std::string& studyDescription)
  {
    studyDescription_ = studyDescription;
  }

  void SetBackgroundColor(uint8_t red,
                          uint8_t green,
                          uint8_t blue);

  void SetForceOpenSlide(bool force)
  {
    forceOpenSlide_ = force;
  }

  void SetReconstructPyramid(bool reconstruct)
  {
    reconstructPyramid_ = reconstruct;
  }

  void SetImagedVolumeWidth(float width);

  virtual std::string GetName() ORTHANC_OVERRIDE
  {
    return studyDescription_;
  }

  virtual std::string GetJobType() ORTHANC_OVERRIDE
  {
    return "wsi";
  }

  virtual bool Execute(std::unique_ptr<Orthanc::TemporaryFile>& upload,
                       SharedLogs& logs,
                       const bool& stopped) ORTHANC_OVERRIDE;

  static bool IsZipFile(const boost::filesystem::path& path);
};
