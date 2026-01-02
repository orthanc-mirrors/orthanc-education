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


var app = new Vue({
  el: '#app',
  data() {
    return {
      config: {},
      username: '',
      projects: [],
      selectedProjectId: '',
      selectedViewer: '',
      filter: '',

      modalProjectParameters: '',
      modalProjectParametersPolicy: '',
      modalProjectParametersPrimaryViewer: '',
      modalProjectParametersSecondaryViewers: []
    }
  },

  computed: {
    projectDescription() {
      var project = this.projects[this.selectedProjectId];
      if (project !== undefined) {
        return project.description;
      } else {
        return '';
      }
    },

    projectPolicy() {
      var project = this.projects[this.selectedProjectId];
      if (project !== undefined) {
        return project.policy;
      } else {
        return '';
      }
    },

    projectViewers() {
      var project = this.projects[this.selectedProjectId];
      if (project !== undefined) {
        return project.secondary_viewers;
      } else {
        return '';
      }
    },

    projectResources() {
      var project = this.projects[this.selectedProjectId];
      if (project !== undefined) {
        return sortObjectsByField(project.resources, 'title');
      } else {
        return '';
      }
    },

    isProjectSelected() {
      var project = this.projects[this.selectedProjectId];
      return (project !== undefined);
    },

    isProjectAccessible() {
      if (this.selectedProjectId === '') {
        return true;
      } else {
        var project = this.projects[this.selectedProjectId];
        return (project !== undefined);
      }
    },

    isInstructorOfSelectedProject() {
      var project = this.projects[this.selectedProjectId];
      if (project !== undefined) {
        return project.role === 'instructor';
      } else {
        return '';
      }
    }
  },

  watch: {
    selectedProjectId(newValue, oldValue) {
      var project = this.projects[newValue];
      if (project !== undefined) {
        this.selectedViewer = project.primary_viewer;
        this.filter = '';
      }
    }
  },

  methods: {
    reloadProjects: function() {
      var that = this;
      axios.get('../api/user-projects')
        .then(function(res) {
          that.projects = res.data.projects;

          var project = that.projects[that.selectedProjectId];
          if (project !== undefined) {
            that.selectedViewer = project.primary_viewer;
          }

          // Display the application after data is loaded to avoid flickering
          const element = document.getElementById('app');
          element.classList.remove('hidden');
        })
        .catch(function() {
          // This presumably indicates that the login has expired, redirect to the root
          window.location.href = '../..';
        });
    },

    getClipboardIconId: function(resource) {
      return 'clipboard-' + resource.level + '-' + resource['resource-id'];
    },

    logout: function() {
      window.location.href = '../do-logout';
    },

    copyViewerToClipboard: function(resource) {
      var that = this;
      doCopyViewerToClipboard(this.selectedViewer, resource, function() {
        // Clear any "check" icon
        const icons = document.getElementsByClassName('clipboard-icon');
        for (var i = 0; i < icons.length; i++) {
          icons[i].classList.remove('fa-check');
          icons[i].classList.add('fa-clipboard');
        }

        const icon = document.getElementById(that.getClipboardIconId(resource));
        icon.classList.remove('fa-clipboard');
        icon.classList.add('fa-check');
      });
    },

    openProjectParameters: function() {
      var project = this.projects[this.selectedProjectId];
      if (project === undefined) {
        return;
      }

      var secondary_viewers = project.secondary_viewers.map((viewer) => viewer.id);

      this.modalProjectParametersPolicy = project.policy;
      this.modalProjectParametersPrimaryViewer = project.primary_viewer;
      this.modalProjectParametersSecondaryViewers = this.config.viewers.map((viewer) => ({
        'id': viewer.id,
        'description': viewer.description,
        'checked': secondary_viewers.includes(viewer.id)
      }));

      this.modalProjectParameters.show();
    },

    changeProjectPolicy() {
      axiosPutAsJson('../api/projects/' + this.selectedProjectId + '/policy',
                     this.modalProjectParametersPolicy);
    },

    changeProjectPrimaryViewer() {
      axiosPutAsJson('../api/projects/' + this.selectedProjectId + '/primary-viewer',
                     this.modalProjectParametersPrimaryViewer);
    },

    changeProjectSecondaryViewers() {
      var secondary_viewers = [];

      this.modalProjectParametersSecondaryViewers.forEach((viewer) => {
        if (viewer.checked) {
          secondary_viewers.push(viewer.id);
        }
      });

      axios.put('../api/projects/' + this.selectedProjectId + '/secondary-viewers', secondary_viewers);
    }
  },

  mounted: function() {
    this.modalProjectParameters = new bootstrap.Modal(document.getElementById('modalProjectParameters'), {});

    this.reloadProjects();

    var that = this;
    axios
      .get('../api/config')
      .then(function(response) {
        that.config = response.data;
        that.username = response.data.user.id || 'Guest';
      });

    document.getElementById('modalProjectParameters').addEventListener('hidden.bs.modal', function (event) {
      that.reloadProjects();
    });

    var params = new URLSearchParams(window.location.search);
    if (params.has('open-project-id')) {
      this.selectedProjectId = params.get('open-project-id');
    }
  }
});
