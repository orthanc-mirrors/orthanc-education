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


function axiosPutAsJson(url, body) {
  return axios.put(url, JSON.stringify(body), {
    headers: {
      'Content-Type': 'application/json'
    }
  });
}


function hasSubstring(description, pattern) {
  if (pattern.length == 0) {
    return true;
  } else {
    var a = description.toLowerCase();
    var b = pattern.toLowerCase();
    return a.indexOf(b) !== -1;
  }
}


function interpretRelativeUrl(relative_url) {
  return new URL(relative_url, new URL('../..', window.location.origin) /* this is the base URL */);
}


function openViewer(viewer, resource) {
  axios.post('../api/resource-viewer-url', {
    viewer: viewer,
    resource: resource
  })
    .then(function(res) {
      var url = interpretRelativeUrl(res.data.relative_url);
      window.open(url.toString(), '_blank').focus();
    })
    .catch(function() {
      alert('The selected Web viewer is not available for this DICOM level');
    });
}


function interpretUrlResponse(res, callback) {
  if ('absolute_url' in res.data) {
    url = new URL(res.data.absolute_url);
  } else {
    url = interpretRelativeUrl(res.data.relative_url);
  }

  return url.href;
}


function doCopyViewerToClipboard(viewer, resource, callback) {
  axios.post('../api/resource-viewer-url', {
    viewer: viewer,
    resource: resource
  })
    .then(function(res) {
      navigator.clipboard.writeText(interpretUrlResponse(res, callback));
      callback();
    })
    .catch(function() {
      alert('The selected Web viewer is not available for this DICOM level');
    });
}


function doCopyListProjectToClipboard(projectId, callback) {
  axios.post('../api/list-project-url', {
    project: projectId
  })
    .then(function(res) {
      navigator.clipboard.writeText(interpretUrlResponse(res, callback));
      callback();
    })
    .catch(function() {
      alert('Cannot generate the link to the list of projects');
    });
}


function sortObjectsByField(arr, field) {
  return arr.sort(function(a, b) {
    if (!(field in a) ||
        !(field in b)) {
      console.error('Missing field "' + field + '"');
      return 0;
    } else {
      if (a[field] > b[field]) {
        return 1;
      } else if (a[field] < b[field]) {
        return -1;
      } else {
        return 0;
      }
    }
  });
}
