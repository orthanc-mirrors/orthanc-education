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


var app = new Vue({
  el: '#app',
  data() {
    return {
      project_name: '',
      project_description: '',
      filter: '',
      resources: [],
      info: {},
      jwt: '',
      viewers: [],
      selected_viewer: 'stone',
      downloads: {}
    }
  },

  methods: {
    getDeepLinkParams: function(resource, full, add_bearer) {
      const params = new URLSearchParams();

      // The parameters that are necessary to call "GenerateViewerUrl()"
      params.append('level', resource.level);
      params.append('resource-id', resource['resource-id']);
      params.append('series-instance-uid', resource['series-instance-uid']);
      params.append('sop-instance-uid', resource['sop-instance-uid']);
      params.append('study-instance-uid', resource['study-instance-uid']);
      params.append('viewer', this.selected_viewer);

      if (full) {
        // Add the additional parameters needed to create the deep link
        params.append('title', resource.title);
        params.append('link-type', 'viewer');

        // Security information that is managed by Moodle
        params.append('aud', this.info['aud']);
        params.append('data', this.info['data']);
        params.append('deployment-id', this.info['deployment-id']);
        params.append('nonce', this.info['nonce']);
      }

      if (add_bearer) {
        params.append('bearer', this.info['orthanc-education-jwt']);
      }

      return params;
    },

    reloadProject: function() {
      var that = this;
      axios.get('project-resources', {
        headers: {
          'Authorization': 'Bearer ' + this.info['orthanc-education-jwt']
        }
      })
        .then(function(res) {
          that.project_name = res.data.name;
          that.project_description = res.data.description;
          that.resources = sortObjectsByField(res.data.resources, 'title');
          that.selected_viewer = res.data.primary_viewer;
          that.viewers = res.data.secondary_viewers;

          that.resources.forEach((resource) => {
            axios.get(resource.preview_url, {
              responseType: 'blob',
              headers: {
                'Authorization': 'Bearer ' + that.info['orthanc-education-jwt']
              },
              params: {
                my_url: resource.preview_url
              }
            })
              .then(function(res2) {
                const blobUrl = URL.createObjectURL(res2.data);
                that.$set(that.downloads, res2.config.params.my_url, blobUrl); // make reactive
              });
          });
        })
        .catch(function(error) {
          // alert(error);
        })
    },

    linkResource: function(resource) {
      var that = this;
      axios.post('create-deep-link', this.getDeepLinkParams(resource, true, false),
                 {
                   // Security information that is managed by the Orthanc LTI plugin
                   headers: {
                     'Authorization': 'Bearer ' + this.info['orthanc-education-jwt']
                   }
                 })
        .then(function(res) {
          that.jwt = res.data;

          // Wait for the DOM to be updated, before submitting the form
          that.$nextTick(function () {
            document.getElementById('lti-return').submit();
          });
        })
        .catch(function (error) {
          alert(error);
        });
    },

    openViewer: function(resource) {
      url = 'open-viewer?' + this.getDeepLinkParams(resource, false, true).toString();
      window.open(url, '_blank').focus();
    },

    linkProjectContent: function(resource) {
      const params = new URLSearchParams();
      params.append('link-type', 'project');

      // Security information that is managed by Moodle
      params.append('aud', this.info['aud']);
      params.append('data', this.info['data']);
      params.append('deployment-id', this.info['deployment-id']);
      params.append('nonce', this.info['nonce']);

      var that = this;
      axios.post('create-deep-link', params,
                 {
                   // Security information that is managed by the Orthanc LTI plugin
                   headers: {
                     'Authorization': 'Bearer ' + this.info['orthanc-education-jwt']
                   }
                 })
        .then(function(res) {
          that.jwt = res.data;

          // Wait for the DOM to be updated, before submitting the form
          that.$nextTick(function () {
            document.getElementById('lti-return').submit();
          });
        })
        .catch(function (error) {
          alert(error);
        });
    }
  },

  mounted: function() {
    var encoded = document.getElementById('info').innerHTML;
    this.info = JSON.parse(atob(encoded));

    this.reloadProject();
  }
});
