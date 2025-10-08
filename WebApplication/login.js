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
      username: '',
      password: ''
    }
  },

  methods: {
    login: function() {
      var that = this;
      axios.post('../do-login', {
        'username' : this.username,
        'password' : this.password
      })
        .then(function(res) {
          var params = new URLSearchParams(window.location.search);
          if (params.has('target')) {
            // Use the target path for redirection, if any specified
            window.location.href = '../..' + params.get('target');
          } else {
            // By default, redirect to the root of the Orthanc REST API,
            // so that the education plugin can properly redirect
            window.location.href = '../..';
          }
        })
        .catch(function(err) {
          that.password = '';
          alert('Bad credentials provided');
        });
    }
  },

  mounted: function() {
  }
});
