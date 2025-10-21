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


#include "ProcessRunner.h"

#include <ChunkedBuffer.h>
#include <OrthancException.h>

#include <cassert>
#include <string.h>
#include <vector>


ProcessRunner::ProcessRunner() :
  started_(false),
  exitCode_(0)
{
  process_ = reproc_new();
  if (!process_)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError, "Cannot create process");
  }
}


ProcessRunner::~ProcessRunner()
{
  assert(process_ != NULL);

  if (started_)
  {
    reproc_wait(process_, REPROC_INFINITE /* wait until the process stops */);
  }

  reproc_destroy(process_);
}


void ProcessRunner::Start(const std::string& command,
                          const std::list<std::string>& args,
                          Stream readFrom)
{
  if (started_)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }

  std::vector<const char*> argv(args.size() + 2);
  argv[0] = command.c_str();

  size_t pos = 1;
  for (std::list<std::string>::const_iterator it = args.begin(); it != args.end(); ++it, pos++)
  {
    argv[pos] = it->c_str();
  }

  assert(pos == argv.size() - 1);
  argv[pos] = NULL;

  reproc_options options;
  memset(&options, 0, sizeof(options));

  options.nonblocking = true;

  switch (readFrom)
  {
  case Stream_Output:
    readFrom_ = REPROC_STREAM_OUT;
    options.redirect.out.type = REPROC_REDIRECT_PIPE;
    options.redirect.err.type = REPROC_REDIRECT_DISCARD;
    break;

  case Stream_Error:
    readFrom_ = REPROC_STREAM_ERR;
    options.redirect.out.type = REPROC_REDIRECT_DISCARD;
    options.redirect.err.type = REPROC_REDIRECT_PIPE;
    break;

  default:
    throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
  }

  if (reproc_start(process_, &argv[0], options) < 0 ||
      // Close stdin as we do not provide input to the child process
      reproc_close(process_, REPROC_STREAM_IN) < 0)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError, "Cannot start process");
  }

  started_ = true;
}


void ProcessRunner::Read(std::string& data)
{
  if (!started_)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }

  Orthanc::ChunkedBuffer buffer;

  uint8_t tmp[4096];

  for (;;)
  {
    int r = reproc_read(process_, readFrom_, tmp, sizeof(tmp));
    if (r <= 0)
    {
      break;
    }
    else
    {
      buffer.AddChunk(tmp, r);
    }
  }

  buffer.Flatten(data);
}


bool ProcessRunner::IsRunning()
{
  if (!started_)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }

  int status = reproc_wait(process_, 0 /* don't wait */);
  if (status == REPROC_ETIMEDOUT)
  {
    return true;
  }
  else
  {
    exitCode_ = status;
    return false;
  }
}


void ProcessRunner::Terminate()
{
  if (!started_)
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);
  }

  reproc_kill(process_);
}
