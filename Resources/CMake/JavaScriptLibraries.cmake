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


set(BASE_URL "https://orthanc.uclouvain.be/downloads/third-party-downloads")

DownloadPackage(
  "102a4386a022f26a3b604e3852fffba8"
  "${BASE_URL}/bootstrap-5.3.3.zip"
  "${CMAKE_CURRENT_BINARY_DIR}/bootstrap-5.3.3")

DownloadPackage(
  "8242afdc5bd44105d9dc9e6535315484"
  "${BASE_URL}/dicom-web/vuejs-2.6.10.tar.gz"
  "${CMAKE_CURRENT_BINARY_DIR}/vue-2.6.10")

DownloadPackage(
  "3e2b4e1522661f7fcf8ad49cb933296c"
  "${BASE_URL}/dicom-web/axios-0.19.0.tar.gz"
  "${CMAKE_CURRENT_BINARY_DIR}/axios-0.19.0")

DownloadPackage(
  "a6145901f233f7d54165d8ade779082e"
  "${BASE_URL}/dicom-web/Font-Awesome-4.7.0.tar.gz"
  "${CMAKE_CURRENT_BINARY_DIR}/Font-Awesome-4.7.0")


set(STATIC_ASSETS_DIR  ${CMAKE_CURRENT_BINARY_DIR}/static-assets)
file(MAKE_DIRECTORY ${STATIC_ASSETS_DIR})

file(COPY
  ${CMAKE_CURRENT_BINARY_DIR}/axios-0.19.0/dist/axios.min.js
  ${CMAKE_CURRENT_BINARY_DIR}/axios-0.19.0/dist/axios.min.map
  ${CMAKE_CURRENT_BINARY_DIR}/bootstrap-5.3.3/dist/js/bootstrap.min.js
  ${CMAKE_CURRENT_BINARY_DIR}/vue-2.6.10/dist/vue.min.js
  DESTINATION
  ${STATIC_ASSETS_DIR}/js
  )

file(COPY
  ${CMAKE_CURRENT_BINARY_DIR}/Font-Awesome-4.7.0/css/font-awesome.min.css
  ${CMAKE_CURRENT_BINARY_DIR}/bootstrap-5.3.3/dist/css/bootstrap.min.css
  ${CMAKE_CURRENT_BINARY_DIR}/bootstrap-5.3.3/dist/css/bootstrap.min.css.map
  DESTINATION
  ${STATIC_ASSETS_DIR}/css
  )

file(COPY
  ${CMAKE_CURRENT_BINARY_DIR}/Font-Awesome-4.7.0/fonts/FontAwesome.otf
  ${CMAKE_CURRENT_BINARY_DIR}/Font-Awesome-4.7.0/fonts/fontawesome-webfont.eot
  ${CMAKE_CURRENT_BINARY_DIR}/Font-Awesome-4.7.0/fonts/fontawesome-webfont.svg
  ${CMAKE_CURRENT_BINARY_DIR}/Font-Awesome-4.7.0/fonts/fontawesome-webfont.ttf
  ${CMAKE_CURRENT_BINARY_DIR}/Font-Awesome-4.7.0/fonts/fontawesome-webfont.woff
  ${CMAKE_CURRENT_BINARY_DIR}/Font-Awesome-4.7.0/fonts/fontawesome-webfont.woff2
  DESTINATION
  ${STATIC_ASSETS_DIR}/fonts
  )

file(COPY
  ${CMAKE_CURRENT_LIST_DIR}/../Images/orthanc-h-negative.png
  ${CMAKE_CURRENT_LIST_DIR}/../Images/orthanc-h.png
  ${CMAKE_CURRENT_LIST_DIR}/../Images/orthanc-negative.png
  ${CMAKE_CURRENT_LIST_DIR}/../Images/orthanc.png
  ${CMAKE_CURRENT_LIST_DIR}/../Images/uclouvain.png
  DESTINATION
  ${STATIC_ASSETS_DIR}/img
  )
