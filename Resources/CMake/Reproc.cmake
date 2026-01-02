# SPDX-FileCopyrightText: 2024-2026 Sebastien Jodogne, EPL UCLouvain, Belgium
# SPDX-License-Identifier: AGPL-3.0-or-later


# Orthanc for Education
# Copyright (C) 2024-2026 Sebastien Jodogne, EPL UCLouvain, Belgium
#
# This program is free software: you can redistribute it and/or
# modify it under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


set(REPROC_SOURCES_DIR ${CMAKE_BINARY_DIR}/reproc-14.2.5)

if (IS_DIRECTORY "${REPROC_SOURCES_DIR}")
  set(FirstRun OFF)
else()
  set(FirstRun ON)
endif()

DownloadPackage(
  "9ea81a0c1eef6b8f76463d41a86e8ddd"
  "https://orthanc.uclouvain.be/downloads/third-party-downloads/reproc-14.2.5.tar.gz"
  "${REPROC_SOURCES_DIR}")

if (FirstRun)
  # Apply the patches
  execute_process(
    COMMAND ${PATCH_EXECUTABLE} -p0 -N -i
    ${CMAKE_CURRENT_LIST_DIR}/Reproc.patch
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    RESULT_VARIABLE Failure
    )

  if (Failure)
    message(FATAL_ERROR "Error while patching a file")
  endif()
endif()

include_directories(${REPROC_SOURCES_DIR}/reproc/include/)

set(REPROC_SOURCES
  ${REPROC_SOURCES_DIR}/reproc/src/drain.c
  ${REPROC_SOURCES_DIR}/reproc/src/options.c
  ${REPROC_SOURCES_DIR}/reproc/src/redirect.c
  ${REPROC_SOURCES_DIR}/reproc/src/reproc.c
  ${REPROC_SOURCES_DIR}/reproc/src/run.c
  ${REPROC_SOURCES_DIR}/reproc/src/strv.c
  )

if (WIN32)
  # Target Windows Vista
  remove_definitions(
    -DWINVER=0x0501
    -D_WIN32_WINNT=0x0501
    )
  add_definitions(
    -DWINVER=0x0600
    -D_WIN32_WINNT=0x0600
    )

  list(APPEND REPROC_SOURCES
    ${REPROC_SOURCES_DIR}/reproc/src/clock.windows.c
    ${REPROC_SOURCES_DIR}/reproc/src/error.windows.c
    ${REPROC_SOURCES_DIR}/reproc/src/handle.windows.c
    ${REPROC_SOURCES_DIR}/reproc/src/init.windows.c
    ${REPROC_SOURCES_DIR}/reproc/src/pipe.windows.c
    ${REPROC_SOURCES_DIR}/reproc/src/process.windows.c
    ${REPROC_SOURCES_DIR}/reproc/src/redirect.windows.c
    ${REPROC_SOURCES_DIR}/reproc/src/utf.windows.c
    )
else()
  list(APPEND REPROC_SOURCES
    ${REPROC_SOURCES_DIR}/reproc/src/clock.posix.c
    ${REPROC_SOURCES_DIR}/reproc/src/error.posix.c
    ${REPROC_SOURCES_DIR}/reproc/src/handle.posix.c
    ${REPROC_SOURCES_DIR}/reproc/src/init.posix.c
    ${REPROC_SOURCES_DIR}/reproc/src/pipe.posix.c
    ${REPROC_SOURCES_DIR}/reproc/src/process.posix.c
    ${REPROC_SOURCES_DIR}/reproc/src/redirect.posix.c
    ${REPROC_SOURCES_DIR}/reproc/src/utf.posix.c
    )
endif()
