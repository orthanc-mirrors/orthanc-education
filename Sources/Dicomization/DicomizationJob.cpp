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


#include "DicomizationJob.h"

#include "ActiveUploads.h"

#include <OrthancException.h>


void DicomizationJob::Worker(DicomizationJob* that)
{
  assert(that != NULL);

  std::unique_ptr<Orthanc::TemporaryFile> upload;

  try
  {
    upload.reset(ActiveUploads::GetInstance().ReleaseTemporaryFile(that->uploadId_));
  }
  catch (Orthanc::OrthancException&)
  {
    boost::mutex::scoped_lock lock(that->mutex_);
    that->status_ = Status_Failure;
    return;
  }

  assert(upload.get() != NULL);

  bool success;

  try
  {
    success = that->dicomizer_->Execute(upload, that->logs_, that->stopped_);
  }
  catch (Orthanc::OrthancException& e)
  {
    success = false;
  }
  catch (...)
  {
    success = false;
  }

  {
    boost::mutex::scoped_lock lock(that->mutex_);
    that->status_ = (success ? Status_Success : Status_Failure);
  }
}


DicomizationJob::DicomizationJob(const std::string& uploadId,
                                 IDicomizer* dicomizer) :
  uploadId_(uploadId),
  dicomizer_(dicomizer),
  stopped_(false),
  status_(Status_Running)
{
  if (dicomizer == NULL)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_NullPointer);
  }

  name_ = dicomizer->GetName();
  jobType_ = dicomizer->GetJobType();
}


DicomizationJob::~DicomizationJob()
{
  if (thread_.joinable())
  {
    thread_.join();
  }
}


void DicomizationJob::Start()
{
  thread_ = boost::thread(Worker, this);
}


Orthanc::JobStepResult DicomizationJob::Step(const std::string& jobId)
{
  boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  {
    boost::mutex::scoped_lock lock(mutex_);
    if (status_ == Status_Success ||
        status_ == Status_Failure)
    {
      return (status_ == Status_Success ?
              Orthanc::JobStepResult::Success() :
              Orthanc::JobStepResult::Failure(Orthanc::ErrorCode_InternalError, ""));
    }
  }

  return Orthanc::JobStepResult::Continue();
}


void DicomizationJob::Reset()
{
  throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
}


void DicomizationJob::Stop(Orthanc::JobStopReason reason)
{
  if (reason == Orthanc::JobStopReason_Canceled)
  {
    stopped_ = true;
  }

  if (thread_.joinable())
  {
    thread_.join();
  }
}


void DicomizationJob::GetPublicContent(Json::Value& value) const
{
  std::string logs;
  const_cast<SharedLogs&>(logs_).GetContent(logs);

  value = Json::objectValue;
  value["logs"] = logs;
  value["name"] = name_;
}


bool DicomizationJob::GetOutput(std::string& output,
                                Orthanc::MimeType& mime,
                                std::string& filename,
                                const std::string& key)
{
  throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
}


bool DicomizationJob::DeleteOutput(const std::string& key)
{
  throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
}


void DicomizationJob::DeleteAllOutputs()
{
  throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
}


bool DicomizationJob::GetUserData(Json::Value& userData) const
{
  return false;
}


#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 12, 10)
void DicomizationJob::SetUserData(const Json::Value& userData)
{
  throw Orthanc::OrthancException(Orthanc::ErrorCode_NotImplemented);
}
#endif



static boost::mutex engineMutex_;
static std::unique_ptr<Orthanc::JobsEngine> engine_;


Orthanc::JobsEngine& DicomizationJob::GetJobsEngine()
{
  boost::mutex::scoped_lock lock(engineMutex_);

  if (engine_.get() == NULL)
  {
    engine_.reset(new Orthanc::JobsEngine(20));  // Only keep 20 completed jobs
    engine_->SetWorkersCount(1);
    engine_->Start();
  }

  return *engine_;
}


void DicomizationJob::FinalizeJobsEngine()
{
  boost::mutex::scoped_lock lock(engineMutex_);

  if (engine_.get() != NULL)
  {
    engine_->Stop();
    engine_.reset(NULL);
  }
}
