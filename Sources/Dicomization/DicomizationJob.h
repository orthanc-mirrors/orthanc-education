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

#include "IDicomizer.h"

#include <JobsEngine/JobsEngine.h>


class DicomizationJob : public Orthanc::IJob
{
private:
  enum Status
  {
    Status_Running,
    Status_Success,
    Status_Failure
  };

  std::string                  uploadId_;
  std::unique_ptr<IDicomizer>  dicomizer_;
  std::string                  name_;
  std::string                  jobType_;
  SharedLogs                   logs_;
  boost::thread                thread_;
  bool                         stopped_;

  boost::mutex                 mutex_;   // To protect "status_"
  Status                       status_;

  static void Worker(DicomizationJob* that);

public:
  DicomizationJob(const std::string& uploadId,
                  IDicomizer* dicomizer);

  virtual ~DicomizationJob();

  virtual void Start() ORTHANC_OVERRIDE;

  virtual Orthanc::JobStepResult Step(const std::string& jobId) ORTHANC_OVERRIDE;

  virtual void Reset() ORTHANC_OVERRIDE;

  virtual void Stop(Orthanc::JobStopReason reason) ORTHANC_OVERRIDE;

  virtual float GetProgress() const ORTHANC_OVERRIDE
  {
    return 0;
  }

  virtual void GetJobType(std::string& target) const ORTHANC_OVERRIDE
  {
    target = jobType_;
  }

  virtual void GetPublicContent(Json::Value& value) const ORTHANC_OVERRIDE;

  virtual bool Serialize(Json::Value& value) const ORTHANC_OVERRIDE
  {
    return false;
  }

  virtual bool GetOutput(std::string& output,
                         Orthanc::MimeType& mime,
                         std::string& filename,
                         const std::string& key) ORTHANC_OVERRIDE;

  virtual bool DeleteOutput(const std::string& key) ORTHANC_OVERRIDE;

  virtual void DeleteAllOutputs() ORTHANC_OVERRIDE;

  virtual bool GetUserData(Json::Value& userData) const ORTHANC_OVERRIDE;

#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 12, 10)
  virtual void SetUserData(const Json::Value& userData) ORTHANC_OVERRIDE;
#endif

  static Orthanc::JobsEngine& GetJobsEngine();

  static void FinalizeJobsEngine();
};
