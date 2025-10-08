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
      config: {},
      projects: [],
      projectsIndex: {},
      images: [],
      projectIdForParameters: '',
      projectIdForImages: '',
      projectIdForContent: '',
      projectForContent: {},
      linkImage: '',

      modalModifyTextTitle: '',
      modalModifyTextValue: '',
      modalModifyText: '',
      modalCreateProject: '',
      modalCreateProjectName: '',
      modalCreateProjectDescription: '',
      modalCreateProjectSave: '',
      modalConfirmTitle: '',
      modalConfirm: '',
      modalProjectParameters: '',
      modalProjectParametersPolicy: '',
      modalProjectParametersPrimaryViewer: '',
      modalProjectParametersSecondaryViewers: [],
      modalProjectParametersBindLti: false,
      modalProjectParametersLtiContextId: false,
      modalEditInstructorsArea: '',
      modalEditInstructors: '',
      modalEditLearnersArea: '',
      modalEditLearners: '',

      editProjectsSwitch: false,
      editImagesSwitch: false,

      configLtiClientId: '',

      // Variables that are used by multiple tabs
      filter: '',
      selectedViewer: ''
    }
  },

  computed: {
    isProjectForContentSelected() {
      return this.projectIdForContent !== '';
    },

    projectViewers() {
      return this.projectForContent.secondary_viewers || '';
    }
  },

  watch: {
    configLtiClientId(newValue, oldValue) {
      axiosPutAsJson('../api/config/lti-client-id', newValue);
    },

    projectIdForContent(newValue, oldValue) {
      this.reloadProjectForContent();
    },

    projectIdForImages(newValue, oldValue) {
      this.reloadImages();
    }
  },

  mounted: function() {
    this.modalModifyText = new bootstrap.Modal(document.getElementById('modalModifyText'), {});
    this.modalCreateProject = new bootstrap.Modal(document.getElementById('modalCreateProject'), {});
    this.modalConfirm = new bootstrap.Modal(document.getElementById('modalConfirm'), {});
    this.modalProjectParameters = new bootstrap.Modal(document.getElementById('modalProjectParameters'), {});
    this.modalEditInstructors = new bootstrap.Modal(document.getElementById('modalEditInstructors'), {});
    this.modalEditLearners = new bootstrap.Modal(document.getElementById('modalEditLearners'), {});

    var that = this;
    axios
      .get('../api/config')
      .then(function(response) {
        that.config = response.data;
        that.configLtiClientId = response.data.lti_client_id;
        that.selectedViewer = that.config.default_viewer;
      });

    this.reloadProjectsParameters();

    // Reload the projects whenever the modal to edit the project parameters is closed
    document.getElementById('modalProjectParameters').addEventListener('hidden.bs.modal', function (event) {
      that.reloadProjectsParameters();
    });

    document.getElementById('pills-images-tab').addEventListener('shown.bs.tab', function (event) {
      that.reloadProjectsParameters();
      that.projectIdForImages = '_no-project';
      that.filter = '';
      that.selectedViewer = that.config.default_viewer;
    });

    document.getElementById('pills-content-tab').addEventListener('shown.bs.tab', function (event) {
      that.projectIdForContent = '';
    });

    // Track the current tab in the hash of the URL
    var hash = window.location.hash.substr(1);
    if (hash !== '') {
      var pill = 'pills-' + hash + '-tab';
      var el = document.getElementById(pill);
      new bootstrap.Tab(el).show();
    }

    document.querySelectorAll('[data-bs-toggle="pill"]').forEach((pill) => {
      pill.addEventListener('shown.bs.tab', (event) => {
        var pill = event.target.id;
        var hash = pill.split('-') [1];
        window.location.hash = '#' + hash;
      });
    });
  },

  methods: {
    getClipboardIconId: function(resource) {
      return 'clipboard-' + resource.level + '-' + resource['resource-id'];
    },

    logout: function() {
      window.location.href = '../do-logout';
    },

    openOrthancExplorer: function(resource) {
      var url = '../../app/explorer.html';

      if (resource !== undefined) {
        if (resource.level === 'Study') {
          url += '#study?uuid=' + encodeURIComponent(resource['resource-id']);
        } else if (resource.level === 'Series') {
          url += '#series?uuid=' + encodeURIComponent(resource['resource-id']);
        } else if (resource.level === 'Instance') {
          url += '#instance?uuid=' + encodeURIComponent(resource['resource-id']);
        } else {
          alert('Cannot generate the link to this resource in Orthanc Explorer');
          return;
        }
      }

      window.open(url, '_blank').focus();
    },

    openOrthancExplorer2: function() {
      window.open('../../ui/app/index.html', '_blank').focus();
    },

    reloadProjectsParameters: function() {
      var that = this;
      axios
        .get('../api/projects')
        .then(function(response) {
          that.projects = response.data;

          that.projectsIndex = {};
          that.projects.forEach((project) => {
            that.projectsIndex[project.id] = project;
          });

          // Display the application after data is loaded to avoid flickering
          var el = document.getElementById('app');
          el.classList.remove('hidden');
        });
    },

    reloadImages: function() {
      var that = this;
      axios
        .post('../api/list-images', {
          project: this.projectIdForImages
        })
        .then(function(response) {
          that.images = response.data;
        })
        .catch(function() {
          that.images = [];
        });
    },

    reloadProjectForContent: function() {
      var that = this;
      axios
        .get('../api/projects/' + this.projectIdForContent)
        .then(function(response) {
          that.projectForContent = response.data;
          that.selectedViewer = response.data.primary_viewer;
          that.filter = '';
          that.linkImage = '';
        });
    },

    launchModalModifyText(title, currentValue, callback) {
      var that = this;
      this.modalModifyTextTitle = title;
      this.modalModifyTextValue = currentValue;
      this.modalModifyTextSave = function(event) {
        that.modalModifyText.hide();
        callback(that.modalModifyTextValue);
      };
      this.modalModifyText.show();
    },

    createProject: function() {
      var that = this;
      this.modalCreateProjectSave = function(event) {
        that.modalCreateProject.hide();
        axios.post('../api/projects', {
          name: that.modalCreateProjectName,
          description: that.modalCreateProjectDescription
        }).then(function() {
          that.reloadProjectsParameters()
        });
      }
      this.modalCreateProject.show();
    },

    deleteProject: function(project) {
      var that = this;
      this.modalConfirmTitle = 'Are you sure to delete this project?';
      this.modalConfirmSave = function() {
        this.modalConfirm.hide();
        axios.delete('../api/projects/' + project.id)
          .then(function() {
            that.reloadProjectsParameters();
          });
      }
      this.modalConfirm.show();
    },

    modifyProjectName: function(project) {
      var that = this;
      this.launchModalModifyText('Modify project name', project.name, function(newValue) {
        axiosPutAsJson('../api/projects/' + project.id + '/name', newValue)
          .then(function() {
            that.reloadProjectsParameters()
          });
      });
    },

    modifyProjectDescription: function(project) {
      var that = this;
      this.launchModalModifyText('Modify project description', project.description, function(newValue) {
        axiosPutAsJson('../api/projects/' + project.id + '/description', newValue)
          .then(function() {
            that.reloadProjectsParameters()
          });
      });
    },

    openProjectParameters: function(project) {
      var secondary_viewers = project.secondary_viewers.map((viewer) => viewer.id);

      this.projectIdForParameters = project.id;
      this.modalProjectParametersPolicy = project.policy;
      this.modalProjectParametersPrimaryViewer = project.primary_viewer;
      this.modalProjectParametersSecondaryViewers = this.config.viewers.map((viewer) => ({
        'id': viewer.id,
        'description': viewer.description,
        'checked': secondary_viewers.includes(viewer.id)
      }));

      if ('lti_context_id' in project) {
        this.modalProjectParametersBindLti = true;
        this.modalProjectParametersLtiContextId = project.lti_context_id;
      } else {
        this.modalProjectParametersBindLti = false;
        this.modalProjectParametersLtiContextId = '';
      }

      this.modalProjectParameters.show();
    },

    changeProjectPolicy: function() {
      axiosPutAsJson('../api/projects/' + this.projectIdForParameters + '/policy',
                     this.modalProjectParametersPolicy);
    },

    changeProjectPrimaryViewer: function() {
      axiosPutAsJson('../api/projects/' + this.projectIdForParameters + '/primary-viewer',
                     this.modalProjectParametersPrimaryViewer);
    },

    changeProjectSecondaryViewers: function() {
      var secondary_viewers = [];

      this.modalProjectParametersSecondaryViewers.forEach((viewer) => {
        if (viewer.checked) {
          secondary_viewers.push(viewer.id);
        }
      });

      axios.put('../api/projects/' + this.projectIdForParameters + '/secondary-viewers', secondary_viewers);
    },

    changeProjectLtiContext: function() {
      var url = '../api/projects/' + this.projectIdForParameters + '/lti-context-id';
      if (this.modalProjectParametersBindLti) {
        axiosPutAsJson(url, this.modalProjectParametersLtiContextId);
      } else {
        axios.delete(url);
      }
    },

    editProjectInstructors: function(project) {
      var that = this;
      this.modalEditInstructorsArea = project.instructors.join('\n');
      this.modalEditInstructorsSave = function(event) {
        this.modalEditInstructors.hide();
        var instructors = this.modalEditInstructorsArea.split(/\r?\n/);
        axios.put('../api/projects/' + project.id + '/instructors', instructors)
          .then(function() {
            that.reloadProjectsParameters();
          });
      }
      this.modalEditInstructors.show();
    },

    editProjectLearners: function(project) {
      var that = this;
      this.modalEditLearnersArea = project.learners.join('\n');
      this.modalEditLearnersSave = function(event) {
        this.modalEditLearners.hide();
        var learners = this.modalEditLearnersArea.split(/\r?\n/);
        axios.put('../api/projects/' + project.id + '/learners', learners)
          .then(function() {
            that.reloadProjectsParameters();
          });
      }
      this.modalEditLearners.show();
    },

    clearClipboardIcons: function() {
      // Clear any "check" icon
      const icons = document.getElementsByClassName('clipboard-icon');
      for (var i = 0; i < icons.length; i++) {
        icons[i].classList.remove('fa-check');
        icons[i].classList.add('fa-clipboard');
      }
    },

    checkClipboardIcon: function(elementId) {
      const icon = document.getElementById(elementId);
      icon.classList.remove('fa-clipboard');
      icon.classList.add('fa-check');
    },

    copyViewerToClipboard: function(resource) {
      var that = this;
      doCopyViewerToClipboard(this.selectedViewer, resource, function() {
        that.clearClipboardIcons();
        that.checkClipboardIcon(that.getClipboardIconId(resource));
      });
    },

    reloadForActivePane: function() {
      const activePane = document.querySelector('#v-pills-tabContent .tab-pane.active.show');

      if (activePane.id == 'pills-content') {
        this.reloadProjectForContent();
      } else if (activePane.id == 'pills-images') {
        this.reloadImages();
      } else {
        console.error('Cannot detect the active pane: ' + activePane.id);
      }
    },

    unlinkResource: function(resource, projectId) {
      var that = this;

      this.modalConfirmTitle = 'Are you sure to remove this image?';
      this.modalConfirmSave = function() {
        this.modalConfirm.hide();

        axios.post('../api/unlink', {
          resource: resource,
          project: projectId
        })
          .then(function(res) {
            that.reloadForActivePane();
          })
          .catch(function() {
            alert('This image cannot be removed');
          });
      }
      this.modalConfirm.show();
    },

    doLinkImage: function() {
      var that = this;
      axios.post('../api/link', {
        data: this.linkImage,
        project: this.projectIdForContent
      })
        .then(function(res) {
          that.reloadProjectForContent();
        })
        .catch(function() {
          alert('Cannot create the link, check out your description of the image');
        });
    },

    modifyImageTitle: function(resource) {
      var that = this;
      this.launchModalModifyText('Modify the title of the image', resource.title, function(newValue) {
        axios.post('../api/change-title', {
          resource: resource,
          title: newValue
        })
          .then(function(res) {
            that.reloadForActivePane();
          });
      });
    },

    copyListProjectToClipboard: function(resource) {
      var that = this;
      doCopyListProjectToClipboard(this.projectIdForContent, function() {
        that.clearClipboardIcons();
        that.checkClipboardIcon('copyListProjectIcon');
      });
    },

    openListProject: function() {
      var url = 'list-projects.html?open-project-id=' + encodeURIComponent(this.projectIdForContent);
      window.open(url, '_blank').focus();
    }
  }
});
