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


#include "WholeSlideImagingDicomizer.h"

#include "../EducationConfiguration.h"
#include "ProcessRunner.h"

#include <Compression/ZipReader.h>
#include <OrthancException.h>
#include <SystemToolbox.h>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/thread.hpp>


bool WholeSlideImagingDicomizer::Unzip(TemporaryDirectory& target,
                                       std::string& unzipMaster,
                                       const Orthanc::TemporaryFile& zip,
                                       const bool& stopped)
{
  std::unique_ptr<Orthanc::ZipReader> reader(Orthanc::ZipReader::CreateFromFile(zip.GetPath()));

  std::string filename, content;
  while (reader->ReadNextFile(filename, content))
  {
    if (stopped)
    {
      return false;
    }

    // Ignore directories in the ZIP
    if (!boost::ends_with(filename, "/"))
    {
      target.WriteFile(filename, content);

      boost::filesystem::path path(target.GetPath(filename));

      const std::string& extension = path.extension().string();

      if (extension == ".mrxs" ||
          extension == ".ndpi" ||
          extension == ".scn" ||
          extension == ".tif" ||
          extension == ".tiff" ||
          extension == ".png" ||
          extension == ".jpg" ||
          extension == ".jpeg")
      {
        if (unzipMaster.empty())
        {
          unzipMaster = path.string();
        }
        else
        {
          throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "ZIP file containing multiple candidate whole-slide images");
        }
      }
    }
  }

  if (unzipMaster.empty())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "ZIP file containing no whole-slide image");
  }

  return true;
}


void WholeSlideImagingDicomizer::PrepareArguments(std::list<std::string>& args) const
{
  if (reconstructPyramid_)
  {
    args.push_back("--pyramid");
    args.push_back("1");
  }

  if (forceOpenSlide_)
  {
    args.push_back("--force-openslide");
    args.push_back("1");
  }

  args.push_back("--color");

  {
    char color[32];
    sprintf(color, "%d,%d,%d", backgroundRed_, backgroundGreen_, backgroundBlue_);
    args.push_back(color);
  }

  const std::string openslide = EducationConfiguration::GetInstance().GetPathToOpenSlide();
  if (!openslide.empty())
  {
    args.push_back("--openslide");
    args.push_back(openslide);
  }
}


bool WholeSlideImagingDicomizer::ExecuteDicomizer(const std::string& dicomizer,
                                                  const std::list<std::string>& args,
                                                  SharedLogs& logs,
                                                  const bool& stopped)
{
  ProcessRunner runner;
  runner.Start(dicomizer, args, ProcessRunner::Stream_Error);

  while (runner.IsRunning())
  {
    if (stopped)
    {
      runner.Terminate();
      return false;
    }

    std::string s;
    runner.Read(s);
    logs.Append(s);

    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }

  {
    std::string s;
    runner.Read(s);
    logs.Append(s);
  }

  return (runner.GetExitCode() == 0);
}


bool WholeSlideImagingDicomizer::UploadDicomToOrthanc(const TemporaryDirectory& target,
                                                      const bool& stopped)
{
  boost::filesystem::directory_iterator iterator(target.GetRoot());
  boost::filesystem::directory_iterator end;

  while (iterator != end)
  {
    if (stopped)
    {
      return false;
    }

    std::string content;

#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 12, 10)
    Orthanc::SystemToolbox::ReadFile(content, iterator->path());
#else
    Orthanc::SystemToolbox::ReadFile(content, iterator->path().string());
#endif

    if (!content.empty())
    {
      Json::Value answer;
      if (!OrthancPlugins::RestApiPost(answer, "/instances", content.c_str(), content.size(), false))
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError, "Cannot upload a DICOM-ized file");
      }
    }

    ++iterator;
  }

  return true;
}


WholeSlideImagingDicomizer::WholeSlideImagingDicomizer() :
  studyDescription_("Whole-slide image"),
  backgroundRed_(255),
  backgroundGreen_(255),
  backgroundBlue_(255),
  forceOpenSlide_(false),
  reconstructPyramid_(true)
{
}


void WholeSlideImagingDicomizer::SetBackgroundColor(uint8_t red,
                                                    uint8_t green,
                                                    uint8_t blue)
{
  backgroundRed_ = red;
  backgroundGreen_ = green;
  backgroundBlue_ = blue;
}


bool WholeSlideImagingDicomizer::Execute(std::unique_ptr<Orthanc::TemporaryFile>& upload,
                                         SharedLogs& logs,
                                         const bool& stopped)
{
  assert(upload.get() != NULL);

  const std::string dicomizer = EducationConfiguration::GetInstance().GetPathToWsiDicomizer();
  if (dicomizer.empty())
  {
    throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "No DICOM-izer is configured for whole-slide images");
  }

  std::unique_ptr<TemporaryDirectory> unzip;
  std::string unzipMaster;

  if (IsZipFile(upload->GetPath()))
  {
    unzip.reset(new TemporaryDirectory);

    if (!Unzip(*unzip, unzipMaster, *upload, stopped))
    {
      return false;
    }

    // We don't need the ZIP file anymore
    upload.reset(NULL);
  }

  Orthanc::TemporaryFile dataset;

  {
    Json::Value json;
    json["StudyDescription"] = studyDescription_;

    std::string s;
    Orthanc::Toolbox::WriteFastJson(s, json);
    dataset.Write(s);
  }

  std::list<std::string> args;
  PrepareArguments(args);

  args.push_back("--dataset");

#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 12, 10)
  args.push_back(dataset.GetPath().string());
#else
  args.push_back(dataset.GetPath());
#endif

  if (unzip.get() == NULL)
  {
#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 12, 10)
    args.push_back(upload->GetPath().string());
#else
    args.push_back(upload->GetPath());
#endif
  }
  else
  {
    args.push_back(unzipMaster);
  }

  std::unique_ptr<TemporaryDirectory> target(new TemporaryDirectory);
  args.push_back("--folder");
  args.push_back(target->GetRoot().string());

  if (!ExecuteDicomizer(dicomizer, args, logs, stopped))
  {
    return false;
  }

  unzip.reset(NULL);
  upload.reset(NULL);

  return UploadDicomToOrthanc(*target, stopped);
}


bool WholeSlideImagingDicomizer::IsZipFile(const boost::filesystem::path& path)
{
  std::string header;

#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 12, 10)
  Orthanc::SystemToolbox::ReadFileRange(header, path, 0, 4, false /* don't throw exception */);
#else
  Orthanc::SystemToolbox::ReadFileRange(header, path.string(), 0, 4, false /* don't throw exception */);
#endif

  if (header.size() != 4)
  {
    return false;
  }
  else
  {
    // https://en.wikipedia.org/wiki/List_of_file_signatures
    const uint8_t *b = reinterpret_cast<const uint8_t*>(header.c_str());
    return ((b[0] == 0x50 && b[1] == 0x4b && b[2] == 0x03 && b[3] == 0x04) ||
            (b[0] == 0x50 && b[1] == 0x4b && b[2] == 0x05 && b[3] == 0x06) ||
            (b[0] == 0x50 && b[1] == 0x4b && b[2] == 0x07 && b[3] == 0x08));
  }
}
