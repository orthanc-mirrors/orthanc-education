#!/usr/bin/python3
# -*- coding: utf-8 -*-


# SPDX-FileCopyrightText: 2024-2025 Sebastien Jodogne, ICTEAM UCLouvain, Belgium
# SPDX-License-Identifier: AGPL-3.0-or-later


# Orthanc for Education
# Copyright (C) 2024-2025 Sebastien Jodogne, EPL UCLouvain, Belgium
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


import argparse
import base64
import io
import json
import os
import pprint
import requests
import sys
import unittest

from PIL import Image


##
## Parse the command-line arguments
##

parser = argparse.ArgumentParser(description = 'Run the integration tests for the Education plugin.')

parser.add_argument('--server',
                    default = 'localhost',
                    help = 'Address of the Orthanc server to test')
parser.add_argument('--rest',
                    type = int,
                    default = 8042,
                    help = 'Port to the REST API')
parser.add_argument('--force', help = 'Do not warn the user',
                    action = 'store_true')
parser.add_argument('options', metavar = 'N', nargs = '*',
                    help='Arguments to Python unittest')

args = parser.parse_args()

if not args.force:
    print("""
WARNING: This test will remove all the content of your
Orthanc instance running on %s!

Are you sure ["yes" to go on]?""" % args.server)

    if sys.stdin.readline().strip() != 'yes':
        print('Aborting...')
        exit(0)


##
## The tests
##

URL = 'http://%s:%d' % (args.server, args.rest)

def AdministratorHeaders():
    return {
        'Mail' : 'admin@uclouvain.be'
    }

def InstructorHeaders():
    return {
        'Mail' : 'instructor@uclouvain.be'
    }

def LearnerHeaders():
    return {
        'Mail' : 'learner@uclouvain.be'
    }

def GuestHeaders():
    return {
    }

def AnyUserHeaders():
    return [
        AdministratorHeaders(),
        InstructorHeaders(),
        LearnerHeaders(),
        GuestHeaders(),
    ]


class Orthanc(unittest.TestCase):
    def setUp(self):
        for patient in requests.get(URL + '/patients', headers = AdministratorHeaders()).json():
            requests.delete(URL + '/patients/%s' % patient, headers = AdministratorHeaders()).raise_for_status()

        for project in requests.get(URL + '/education/api/projects', headers = AdministratorHeaders()).json():
            requests.delete(URL + '/education/api/projects/%s' % project['id'], headers = AdministratorHeaders()).raise_for_status()


    def test_config(self):
        requests.put(URL + '/education/api/config/lti-client-id', json.dumps(''), headers = AdministratorHeaders()).raise_for_status()

        config = requests.get(URL + '/education/api/config', headers = AdministratorHeaders()).json()
        self.assertEqual('admin', config['user']['role'])
        self.assertEqual('admin@uclouvain.be', config['user']['id'])
        self.assertEqual(0, len(config['user']['instructor_of']))
        self.assertEqual(0, len(config['user']['learner_of']))
        self.assertFalse('lti_project_id' in config['user'])

        self.assertEqual('stone', config['default_viewer'])
        self.assertTrue('has_orthanc_explorer_2' in config)
        self.assertEqual('education-', config['label_prefix'])
        self.assertEqual('', config['lti_client_id'])
        self.assertEqual(False, config['lti_enabled'])
        self.assertEqual('', config['lti_platform_keys_url'])
        self.assertEqual('', config['lti_platform_redirection_url'])
        self.assertEqual('', config['lti_platform_url'])

        requests.put(URL + '/education/api/config/lti-client-id', json.dumps('client'), headers = AdministratorHeaders()).raise_for_status()
        config = requests.get(URL + '/education/api/config', headers = AdministratorHeaders()).json()
        self.assertEqual('client', config['lti_client_id'])

        config = requests.get(URL + '/education/api/config', headers = InstructorHeaders()).json()
        self.assertEqual('standard', config['user']['role'])
        self.assertEqual('instructor@uclouvain.be', config['user']['id'])
        self.assertEqual(0, len(config['user']['instructor_of']))
        self.assertEqual(0, len(config['user']['learner_of']))
        self.assertFalse('lti_project_id' in config['user'])

        config = requests.get(URL + '/education/api/config', headers = LearnerHeaders()).json()
        self.assertEqual('standard', config['user']['role'])
        self.assertEqual('learner@uclouvain.be', config['user']['id'])
        self.assertEqual(0, len(config['user']['instructor_of']))
        self.assertEqual(0, len(config['user']['learner_of']))
        self.assertFalse('lti_project_id' in config['user'])

        config = requests.get(URL + '/education/api/config', headers = GuestHeaders()).json()
        self.assertEqual('guest', config['user']['role'])
        self.assertFalse('id' in config['user'])
        self.assertEqual(0, len(config['user']['instructor_of']))
        self.assertEqual(0, len(config['user']['learner_of']))
        self.assertFalse('lti_project_id' in config['user'])


    def test_root_redirection(self):
        path = requests.get(URL, headers = AdministratorHeaders(), allow_redirects=False).headers['Location']
        self.assertEqual('education/app/dashboard.html', path)

        path = requests.get(URL, headers = InstructorHeaders(), allow_redirects=False).headers['Location']
        self.assertEqual('education/app/list-projects.html', path)

        path = requests.get(URL, headers = LearnerHeaders(), allow_redirects=False).headers['Location']
        self.assertEqual('education/app/list-projects.html', path)

        path = requests.get(URL, headers = GuestHeaders(), allow_redirects=False).headers['Location']
        self.assertEqual('education/app/login.html', path)


    def test_login_html(self):
        path = requests.get(URL + '/education/app/login.html', headers = AdministratorHeaders(), allow_redirects=False).headers['Location']
        self.assertEqual('../../education/app/dashboard.html', path)

        path = requests.get(URL + '/education/app/login.html', headers = InstructorHeaders(), allow_redirects=False).headers['Location']
        self.assertEqual('../../education/app/list-projects.html', path)

        path = requests.get(URL + '/education/app/login.html', headers = LearnerHeaders(), allow_redirects=False).headers['Location']
        self.assertEqual('../../education/app/list-projects.html', path)

        r = requests.get(URL + '/education/app/login.html', headers = GuestHeaders(), allow_redirects=False)
        self.assertFalse('Location' in r.headers)
        self.assertEqual('text/html', r.headers['Content-Type'])


    def test_logout(self):
        for headers in AnyUserHeaders():
            session = requests.session()
            session.cookies.clear()

            if args.server == 'localhost':
                domain = 'localhost.local'
            else:
                domain = args.server

            session.cookies.set('orthanc-education-user', 'a', domain = domain)
            session.cookies.set('orthanc-education-oidc', 'b', domain = domain)
            session.cookies.set('orthanc-education-lti', 'c', domain = domain)
            session.cookies.set('orthanc-education-nope', 'd', domain = domain)

            r = session.get(URL + '/education/do-logout', headers = headers)

            # All the cookies have been cleared by "do-logout", except "orthanc-education-nope"
            self.assertEqual(1, len(session.cookies.keys()))
            self.assertEqual('orthanc-education-nope', session.cookies.keys() [0])


    def test_get_routes_permissions(self):
        # Public routes
        for route in [
            '/education/app/list-projects.html',
            '/education/app/list-projects.js',
            '/education/app/login.js',
            '/education/app/toolbox.js',
            '/education/do-logout',
        ]:
            self.assertEqual(200, requests.get(URL + route, headers = AdministratorHeaders()).status_code)
            self.assertEqual(200, requests.get(URL + route, headers = InstructorHeaders()).status_code)
            self.assertEqual(200, requests.get(URL + route, headers = LearnerHeaders()).status_code)
            self.assertEqual(200, requests.get(URL + route, headers = GuestHeaders()).status_code)

        # Administrator credentials
        for route in [
            '/education/app/dashboard.html',
            '/education/app/dashboard.js',
        ]:
            self.assertEqual(200, requests.get(URL + route, headers = AdministratorHeaders()).status_code)
            self.assertEqual(403, requests.get(URL + route, headers = InstructorHeaders()).status_code)
            self.assertEqual(403, requests.get(URL + route, headers = LearnerHeaders()).status_code)
            self.assertEqual(403, requests.get(URL + route, headers = GuestHeaders()).status_code)


    def check_url(self, url, request):
            self.assertEqual(url, request.json() ['relative_url'])
            self.assertEqual('http://my-public/%s' % request.json() ['relative_url'], request.json() ['absolute_url'])


    def test_list_project_url(self):
        for headers in AnyUserHeaders():
            r = requests.post(URL + '/education/api/list-project-url', json.dumps({
                'project' : 'toto',
            }), headers = headers)
            self.check_url('education/app/list-projects.html?open-project-id=toto', r)


    def test_list_project_url(self):
        for headers in AnyUserHeaders():
            body = {
                'resource' : {
                    'study-instance-uid' : 'tata',
                    'resource-id' : 'toto',
                    'level' : 'Study',
                }
            }

            body['viewer'] = 'stone'
            r = requests.post(URL + '/education/api/resource-viewer-url', json.dumps(body), headers = headers)
            self.check_url('stone-webviewer/index.html?study=tata', r)

            body['viewer'] = 'volview'
            r = requests.post(URL + '/education/api/resource-viewer-url', json.dumps(body), headers = headers)
            self.check_url('volview/index.html?names=[archive.zip]&urls=[../studies/toto/archive]', r)

            body['viewer'] = 'ohif-basic'
            r = requests.post(URL + '/education/api/resource-viewer-url', json.dumps(body), headers = headers)
            self.check_url('ohif/viewer?StudyInstanceUIDs=tata', r)

            body['viewer'] = 'ohif-volume'
            r = requests.post(URL + '/education/api/resource-viewer-url', json.dumps(body), headers = headers)
            self.check_url('ohif/viewer?hangingprotocolId=mprAnd3DVolumeViewport&StudyInstanceUIDs=tata', r)

            body['viewer'] = 'ohif-tumor'
            r = requests.post(URL + '/education/api/resource-viewer-url', json.dumps(body), headers = headers)
            self.check_url('ohif/tmtv?StudyInstanceUIDs=tata', r)

            body['viewer'] = 'ohif-segmentation'
            r = requests.post(URL + '/education/api/resource-viewer-url', json.dumps(body), headers = headers)
            self.check_url('ohif/segmentation?StudyInstanceUIDs=tata', r)

            body = {
                'resource' : {
                    'study-instance-uid' : 'tata',
                    'series-instance-uid' : 'tutu',
                    'resource-id' : 'toto',
                    'level' : 'Series',
                }
            }

            body['viewer'] = 'stone'
            r = requests.post(URL + '/education/api/resource-viewer-url', json.dumps(body), headers = headers)
            self.check_url('stone-webviewer/index.html?study=tata&series=tutu', r)

            body['viewer'] = 'wsi'
            r = requests.post(URL + '/education/api/resource-viewer-url', json.dumps(body), headers = headers)
            self.check_url('wsi/app/viewer.html?series=toto', r)

            body['viewer'] = 'volview'
            r = requests.post(URL + '/education/api/resource-viewer-url', json.dumps(body), headers = headers)
            self.check_url('volview/index.html?names=[archive.zip]&urls=[../series/toto/archive]', r)

            body = {
                'resource' : {
                    'study-instance-uid' : 'tata',
                    'series-instance-uid' : 'tutu',
                    'sop-instance-uid' : 'titi',
                    'resource-id' : 'toto',
                    'level' : 'Instance',
                }
            }

            body['viewer'] = 'wsi'
            r = requests.post(URL + '/education/api/resource-viewer-url', json.dumps(body), headers = headers)
            self.check_url('wsi/app/viewer.html?instance=toto', r)


    def test_create_project(self):
        for headers in [
                InstructorHeaders(),
                LearnerHeaders(),
                GuestHeaders(),
        ]:
            self.assertEqual(403, requests.get(URL + '/education/api/projects', headers = headers).status_code)

        projects = requests.get(URL + '/education/api/projects', headers = AdministratorHeaders()).json()
        self.assertEqual(0, len(projects))

        body = {
            'name' : 'Hello',
            'description' : 'World',
        }

        for headers in [
                InstructorHeaders(),
                LearnerHeaders(),
                GuestHeaders(),
        ]:
            self.assertEqual(403, requests.post(URL + '/education/api/projects', json.dumps(body), headers = headers).status_code)

        r = requests.post(URL + '/education/api/projects', json.dumps(body), headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(r))

        projects = requests.get(URL + '/education/api/projects', headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(projects))
        self.assertEqual(r['id'], projects[0]['id'])

        self.assertEqual('Hello', projects[0]['name'])
        self.assertEqual('World', projects[0]['description'])
        self.assertEqual(0, len(projects[0]['instructors']))
        self.assertEqual(0, len(projects[0]['learners']))
        self.assertEqual('hidden', projects[0]['policy'])
        self.assertEqual('stone', projects[0]['primary_viewer'])
        self.assertEqual(0, len(projects[0]['secondary_viewers']))

        for headers in [
                InstructorHeaders(),
                LearnerHeaders(),
                GuestHeaders(),
        ]:
            self.assertEqual(403, requests.get(URL + '/education/api/projects/%s' % projects[0]['id'], headers = headers).status_code)

        project = requests.get(URL + '/education/api/projects/%s' % projects[0]['id'], headers = AdministratorHeaders()).json()
        self.assertEqual(project, projects[0])

        for headers in [
                InstructorHeaders(),
                LearnerHeaders(),
                GuestHeaders(),
        ]:
            self.assertEqual(403, requests.delete(URL + '/education/api/projects/%s' % projects[0]['id'], headers = headers).status_code)

        requests.delete(URL + '/education/api/projects/%s' % projects[0]['id'], headers = AdministratorHeaders()).raise_for_status()

        projects = requests.get(URL + '/education/api/projects', headers = AdministratorHeaders()).json()
        self.assertEqual(0, len(projects))


    def test_list_user_projects(self):
        def CheckCountProjects(countAdministrator, roleAdministrator,
                               countInstructor, roleInstructor,
                               countLearner, roleLearner,
                               countGuest, roleGuest):
            for i in [
                    (AdministratorHeaders(), countAdministrator, roleAdministrator),
                    (InstructorHeaders(), countInstructor, roleInstructor),
                    (LearnerHeaders(), countLearner, roleLearner),
                    (GuestHeaders(), countGuest, roleGuest),
            ]:
                lst = requests.get(URL + '/education/api/user-projects', headers = i[0]).json()
                self.assertEqual(1, len(lst))
                self.assertEqual(i[1], len(lst['projects']))
                keys = list(lst['projects'].keys())
                assert(len(keys) <= 1)
                if len(keys) == 1:
                    self.assertEqual(i[2], lst['projects'][keys[0]]['role'])

        CheckCountProjects(0, '', 0, '', 0, '', 0, '')

        project = requests.post(URL + '/education/api/projects', json.dumps({
            'name' : 'Hello',
            'description' : 'World'
        }), headers = AdministratorHeaders()).json() ['id']

        lst = requests.get(URL + '/education/api/user-projects', headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(lst['projects']))
        self.assertTrue(project in lst['projects'])
        self.assertEqual('Hello', lst['projects'][project]['name'])
        self.assertEqual('World', lst['projects'][project]['description'])
        self.assertEqual('hidden', lst['projects'][project]['policy'])
        self.assertEqual('stone', lst['projects'][project]['primary_viewer'])
        self.assertEqual(0, len(lst['projects'][project]['resources']))
        self.assertEqual('instructor', lst['projects'][project]['role'])
        self.assertEqual(1, len(lst['projects'][project]['secondary_viewers']))
        self.assertEqual('stone', lst['projects'][project]['secondary_viewers'][0]['id'])

        projects = requests.get(URL + '/education/api/projects', headers = AdministratorHeaders()).json()
        self.assertEqual(projects[0]['id'], project)

        CheckCountProjects(1, 'instructor', 0, '', 0, '', 0, '')

        requests.put(URL + '/education/api/projects/%s/policy' % project, json.dumps('hidden'),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 0, '', 0, '', 0, '')

        requests.put(URL + '/education/api/projects/%s/instructors' % project, json.dumps([ 'instructor@uclouvain.be' ]),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 1, 'instructor', 0, '', 0, '')

        requests.put(URL + '/education/api/projects/%s/instructors' % project, json.dumps([ ]),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 0, '', 0, '', 0, '')

        requests.put(URL + '/education/api/projects/%s/learners' % project, json.dumps([ 'learner@uclouvain.be' ]),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 0, '', 0, '', 0, '')

        requests.put(URL + '/education/api/projects/%s/learners' % project, json.dumps([ ]),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 0, '', 0, '', 0, '')

        requests.put(URL + '/education/api/projects/%s/policy' % project, json.dumps('active'),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 0, '', 0, '', 0, '')

        requests.put(URL + '/education/api/projects/%s/instructors' % project, json.dumps([ 'instructor@uclouvain.be' ]),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 1, 'instructor', 0, '', 0, '')

        requests.put(URL + '/education/api/projects/%s/instructors' % project, json.dumps([ ]),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 0, '', 0, '', 0, '')

        requests.put(URL + '/education/api/projects/%s/learners' % project, json.dumps([ 'learner@uclouvain.be' ]),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 0, '', 1, 'learner', 0, '')

        requests.put(URL + '/education/api/projects/%s/learners' % project, json.dumps([ ]),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 0, '', 0, '', 0, '')

        requests.put(URL + '/education/api/projects/%s/policy' % project, json.dumps('public'),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 1, 'learner', 1, 'learner', 1, 'learner')

        requests.put(URL + '/education/api/projects/%s/instructors' % project, json.dumps([ 'instructor@uclouvain.be' ]),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 1, 'instructor', 1, 'learner', 1, 'learner')

        requests.put(URL + '/education/api/projects/%s/instructors' % project, json.dumps([ ]),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 1, 'learner', 1, 'learner', 1, 'learner')

        requests.put(URL + '/education/api/projects/%s/learners' % project, json.dumps([ 'learner@uclouvain.be' ]),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 1, 'learner', 1, 'learner', 1, 'learner')

        requests.put(URL + '/education/api/projects/%s/learners' % project, json.dumps([ ]),
                     headers = AdministratorHeaders()).raise_for_status()
        CheckCountProjects(1, 'instructor', 1, 'learner', 1, 'learner', 1, 'learner')


    def test_change_project_parameter(self):
        i = requests.post(URL + '/education/api/projects', json.dumps({
            'name' : 'Hello',
            'description' : 'World'
        }), headers = AdministratorHeaders()).json() ['id']

        project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
        self.assertEqual(8, len(project))
        self.assertEqual('Hello', project['name'])
        self.assertEqual('World', project['description'])
        self.assertEqual(i, project['id'])
        self.assertEqual(0, len(project['instructors']))
        self.assertEqual(0, len(project['learners']))
        self.assertEqual('hidden', project['policy'])
        self.assertEqual('stone', project['primary_viewer'])
        self.assertEqual(0, len(project['secondary_viewers']))
        self.assertFalse('lti-context-id' in project)

        ## The parameters below can only be changed by the administrator, as long as no instructor is associated with the project

        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/learners' % i, json.dumps([ 'a' ]), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/learners' % i, json.dumps([ 'a' ]), headers = LearnerHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/learners' % i, json.dumps([ 'a' ]), headers = GuestHeaders()).status_code)
        requests.put(URL + '/education/api/projects/%s/learners' % i, json.dumps([ 'c', 'learner@uclouvain.be' ]), headers = AdministratorHeaders()).raise_for_status()
        project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
        v = project['learners']
        self.assertEqual(2, len(v))
        self.assertTrue('c' in v)
        self.assertTrue('learner@uclouvain.be' in v)

        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/name' % i, json.dumps('Nope'), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/name' % i, json.dumps('Nope'), headers = LearnerHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/name' % i, json.dumps('Nope'), headers = GuestHeaders()).status_code)
        requests.put(URL + '/education/api/projects/%s/name' % i, json.dumps('New name'), headers = AdministratorHeaders()).raise_for_status()
        project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
        self.assertEqual('New name', project['name'])

        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/description' % i, json.dumps('Nope'), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/description' % i, json.dumps('Nope'), headers = LearnerHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/description' % i, json.dumps('Nope'), headers = GuestHeaders()).status_code)
        requests.put(URL + '/education/api/projects/%s/description' % i, json.dumps('New description'), headers = AdministratorHeaders()).raise_for_status()
        project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
        self.assertEqual('New description', project['description'])

        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/policy' % i, json.dumps('active'), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/policy' % i, json.dumps('active'), headers = LearnerHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/policy' % i, json.dumps('active'), headers = GuestHeaders()).status_code)
        requests.put(URL + '/education/api/projects/%s/policy' % i, json.dumps('active'), headers = AdministratorHeaders()).raise_for_status()
        project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
        self.assertEqual('active', project['policy'])

        for viewer in [ 'stone', 'volview', 'wsi', 'ohif-basic', 'ohif-volume', 'ohif-tumor', 'ohif-segmentation' ]:
            self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/primary-viewer' % i, json.dumps(viewer), headers = InstructorHeaders()).status_code)
            self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/primary-viewer' % i, json.dumps(viewer), headers = LearnerHeaders()).status_code)
            self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/primary-viewer' % i, json.dumps(viewer), headers = GuestHeaders()).status_code)

            requests.put(URL + '/education/api/projects/%s/primary-viewer' % i, json.dumps(viewer), headers = AdministratorHeaders()).raise_for_status()

            project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
            self.assertEqual(viewer, project['primary_viewer'])

        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/secondary-viewers' % i, json.dumps([ 'wsi', 'ohif-basic' ]), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/secondary-viewers' % i, json.dumps([ 'wsi', 'ohif-basic' ]), headers = LearnerHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/secondary-viewers' % i, json.dumps([ 'wsi', 'ohif-basic' ]), headers = GuestHeaders()).status_code)
        requests.put(URL + '/education/api/projects/%s/secondary-viewers' % i, json.dumps([ 'wsi', 'ohif-basic' ]), headers = AdministratorHeaders()).raise_for_status()
        project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
        v = list(map(lambda x: x['id'], project['secondary_viewers']))
        self.assertEqual(2, len(v))
        self.assertTrue('wsi' in v)
        self.assertTrue('ohif-basic' in v)

        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/lti-context-id' % i, json.dumps('context'), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/lti-context-id' % i, json.dumps('context'), headers = LearnerHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/lti-context-id' % i, json.dumps('context'), headers = GuestHeaders()).status_code)
        requests.put(URL + '/education/api/projects/%s/lti-context-id' % i, json.dumps('context'), headers = AdministratorHeaders()).raise_for_status()
        project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
        self.assertEqual(9, len(project))
        self.assertEqual('context', project['lti_context_id'])

        self.assertEqual(403, requests.delete(URL + '/education/api/projects/%s/lti-context-id' % i, headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.delete(URL + '/education/api/projects/%s/lti-context-id' % i, headers = LearnerHeaders()).status_code)
        self.assertEqual(403, requests.delete(URL + '/education/api/projects/%s/lti-context-id' % i, headers = GuestHeaders()).status_code)
        requests.delete(URL + '/education/api/projects/%s/lti-context-id' % i, headers = AdministratorHeaders()).raise_for_status()
        project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
        self.assertEqual(8, len(project))
        self.assertFalse('lti-context-id' in project)

        ## Associate the instructor with the project

        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/instructors' % i, json.dumps([ 'a', 'instructor@uclouvain.be' ]), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/instructors' % i, json.dumps([ 'a', 'instructor@uclouvain.be' ]), headers = LearnerHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/instructors' % i, json.dumps([ 'a', 'instructor@uclouvain.be' ]), headers = GuestHeaders()).status_code)
        requests.put(URL + '/education/api/projects/%s/instructors' % i, json.dumps([ 'a', 'instructor@uclouvain.be' ]), headers = AdministratorHeaders()).raise_for_status()
        project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
        v = project['instructors']
        self.assertEqual(2, len(v))
        self.assertTrue('a' in v)
        self.assertTrue('instructor@uclouvain.be' in v)

        ## The parameters below can also be changed by the instructors (the same tests failed above)

        requests.put(URL + '/education/api/projects/%s/policy' % i, json.dumps('public'), headers = InstructorHeaders()).raise_for_status()
        project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
        self.assertEqual('public', project['policy'])

        requests.put(URL + '/education/api/projects/%s/primary-viewer' % i, json.dumps('wsi'), headers = InstructorHeaders()).raise_for_status()
        project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
        self.assertEqual('wsi', project['primary_viewer'])

        requests.put(URL + '/education/api/projects/%s/secondary-viewers' % i, json.dumps([ 'stone' ]), headers = InstructorHeaders()).raise_for_status()
        project = requests.get(URL + '/education/api/projects/%s' % i, headers = AdministratorHeaders()).json()
        v = list(map(lambda x: x['id'], project['secondary_viewers']))
        self.assertEqual(1, len(v))
        self.assertTrue('stone' in v)

        ## The other parameters are still not allowed for the instructor

        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/name' % i, json.dumps('Nope'), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/description' % i, json.dumps('Nope'), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/instructors' % i, json.dumps([ 'a', 'instructor@uclouvain.be' ]), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/learners' % i, json.dumps([ 'a' ]), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.put(URL + '/education/api/projects/%s/lti-context-id' % i, json.dumps('context'), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.delete(URL + '/education/api/projects/%s/lti-context-id' % i, headers = InstructorHeaders()).status_code)


    def create_test_instance_id(self):
        with open(os.path.join(os.path.dirname(__file__), '..', 'Images', 'orthanc-h.png'), 'rb') as f:
            content = f.read()

        pixelData = base64.b64encode(content).decode('ascii')

        return requests.post(URL + '/tools/create-dicom',
                             json.dumps({
                                 'Content' : 'data:image/png;base64,%s' % pixelData,
                                 'Tags' : {
                                     'PatientName' : 'TEST',
                                     'StudyDescription' : 'MY^STUDY',
                                 }
                             }),
                             headers = AdministratorHeaders()).json() ['ID']


    def test_link_unlink(self):
        lst2 = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : '_all-studies'
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(0, len(lst2))

        lst2 = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : '_unused-studies'
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(0, len(lst2))

        lst2 = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : '_unused-series'
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(0, len(lst2))

        instance = self.create_test_instance_id()
        tags = requests.get(URL + '/instances/%s/tags?short' % instance, headers = AdministratorHeaders()).json()
        labels = requests.get(URL + '/instances/%s/labels' % instance, headers = AdministratorHeaders()).json()
        self.assertEqual(0, len(labels))

        project = requests.post(URL + '/education/api/projects', json.dumps({
            'name' : 'Hello',
            'description' : 'World',
        }), headers = AdministratorHeaders()).json() ['id']

        lst = requests.get(URL + '/education/api/user-projects', headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(lst['projects']))
        self.assertEqual(0, len(lst['projects'][project]['resources']))

        lst2 = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : '_all-studies'
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(lst2))

        lst2 = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : '_unused-studies'
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(lst2))

        lst2 = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : '_unused-series'
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(lst2))

        body = {
            'resource' : {
                'resource-id' : instance,
                'level' : 'Instance',
            },
            'project' : project,
        }

        self.assertEqual(403, requests.post(URL + '/education/api/link', json.dumps(body), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.post(URL + '/education/api/link', json.dumps(body), headers = LearnerHeaders()).status_code)
        self.assertEqual(403, requests.post(URL + '/education/api/link', json.dumps(body), headers = GuestHeaders()).status_code)
        requests.post(URL + '/education/api/link', json.dumps(body), headers = AdministratorHeaders()).raise_for_status()

        lst = requests.get(URL + '/education/api/user-projects', headers = AdministratorHeaders()).json()
        resources = lst['projects'][project]['resources']
        self.assertEqual(1, len(resources))
        self.assertEqual('Instance', resources[0]['level'])
        self.assertEqual(instance, resources[0]['resource-id'])
        self.assertEqual('TEST - MY^STUDY', resources[0]['title'])
        self.assertEqual([ project ], resources[0]['projects'])
        self.assertEqual(tags['0020,000d'], resources[0]['study-instance-uid'])
        self.assertEqual(tags['0020,000e'], resources[0]['series-instance-uid'])
        self.assertEqual(tags['0008,0018'], resources[0]['sop-instance-uid'])
        preview_url = resources[0]['preview_url']

        lst2 = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : project,
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(lst2))
        self.assertEqual(lst2[0], resources[0])

        labels = requests.get(URL + '/instances/%s/labels' % instance, headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(labels))
        self.assertTrue('education-%s' % project in labels)

        self.assertEqual(404, requests.get(URL + '/instances/%s/metadata/9520' % instance, headers = AdministratorHeaders()).status_code)

        body['title'] = 'Hello'
        requests.post(URL + '/education/api/change-title', json.dumps(body), headers = AdministratorHeaders()).raise_for_status()
        lst = requests.get(URL + '/education/api/user-projects', headers = AdministratorHeaders()).json()
        self.assertEqual('Hello', lst['projects'][project]['resources'][0]['title'])

        metadata = requests.get(URL + '/instances/%s/metadata/9520' % instance, headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(metadata))
        self.assertEqual('Hello', metadata['title'])

        # "preview_url" is relative to "deep.html" and "list-projects.html"
        self.assertEqual('../api/preview-instance/%s' % instance, preview_url)
        preview = requests.get(URL + '/education/app/' + preview_url, headers = AdministratorHeaders())
        self.assertEqual('image/jpeg', preview.headers['Content-Type'])
        im = Image.open(io.BytesIO(preview.content))
        self.assertEqual(128, im.size[0])
        self.assertEqual(128, im.size[1])

        metadata = requests.get(URL + '/instances/%s/metadata/9521' % instance, headers = AdministratorHeaders()).json()
        self.assertEqual(2, len(metadata))
        self.assertTrue('last-update' in metadata)
        self.assertEqual(preview.content, base64.b64decode(metadata['jpeg']))

        body = {
            'resource' : {
                'resource-id' : instance,
                'level' : 'Instance',
            },
            'project' : project,
        }

        self.assertEqual(403, requests.post(URL + '/education/api/unlink', json.dumps(body), headers = InstructorHeaders()).status_code)
        self.assertEqual(403, requests.post(URL + '/education/api/unlink', json.dumps(body), headers = LearnerHeaders()).status_code)
        self.assertEqual(403, requests.post(URL + '/education/api/unlink', json.dumps(body), headers = GuestHeaders()).status_code)
        requests.post(URL + '/education/api/unlink', json.dumps(body), headers = AdministratorHeaders()).raise_for_status()

        lst = requests.get(URL + '/education/api/user-projects', headers = AdministratorHeaders()).json()
        self.assertEqual(0, len(lst['projects'][project]['resources']))

        labels = requests.get(URL + '/instances/%s/labels' % instance, headers = AdministratorHeaders()).json()
        self.assertEqual(0, len(labels))

        lst = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : project,
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(0, len(lst))


    def test_delete_project(self):
        instance = self.create_test_instance_id()
        study = requests.get(URL + '/instances/%s/study' % instance, headers = AdministratorHeaders()).json() ['ID']
        series = requests.get(URL + '/instances/%s/series' % instance, headers = AdministratorHeaders()).json() ['ID']

        project = requests.post(URL + '/education/api/projects', json.dumps({
            'name' : 'Hello',
            'description' : 'World',
        }), headers = AdministratorHeaders()).json() ['id']

        lst = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : project,
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(0, len(lst))

        requests.post(URL + '/education/api/link', json.dumps({
            'resource' : {
                'resource-id' : study,
                'level' : 'Study',
            },
            'project' : project,
        }), headers = AdministratorHeaders()).raise_for_status()

        requests.post(URL + '/education/api/link', json.dumps({
            'resource' : {
                'resource-id' : series,
                'level' : 'Series',
            },
            'project' : project,
        }), headers = AdministratorHeaders()).raise_for_status()

        requests.post(URL + '/education/api/link', json.dumps({
            'resource' : {
                'resource-id' : instance,
                'level' : 'Instance',
            },
            'project' : project,
        }), headers = AdministratorHeaders()).raise_for_status()

        labels = requests.get(URL + '/studies/%s/labels' % study, headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(labels))
        self.assertTrue('education-%s' % project in labels)

        labels = requests.get(URL + '/series/%s/labels' % series, headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(labels))
        self.assertTrue('education-%s' % project in labels)

        labels = requests.get(URL + '/instances/%s/labels' % instance, headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(labels))
        self.assertTrue('education-%s' % project in labels)

        lst = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : '_all-studies'
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(lst))

        lst = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : '_unused-studies'
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(0, len(lst))

        lst = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : '_unused-series'
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(0, len(lst))

        lst = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : project,
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(3, len(lst))

        requests.delete(URL + '/education/api/projects/%s' % project, headers = AdministratorHeaders()).raise_for_status()

        lst = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : '_all-studies'
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(lst))

        lst = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : '_unused-studies'
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(lst))

        lst = requests.post(URL + '/education/api/list-images', json.dumps({
            'project' : '_unused-series'
        }), headers = AdministratorHeaders()).json()
        self.assertEqual(1, len(lst))


    def test_dicom_permissions(self):
        def CheckForbidden(path, headers = {}):
            self.assertEqual(307, requests.get(URL + path, headers = headers, allow_redirects = False).status_code)

        def CheckGranted(path, headers = {}):
            self.assertEqual(200, requests.get(URL + path, headers = headers, allow_redirects = False).status_code)

        def CheckPolicyPath(path):
            requests.put(URL + '/education/api/projects/%s/instructors' % project, json.dumps([ ]),
                         headers = AdministratorHeaders()).raise_for_status()
            requests.put(URL + '/education/api/projects/%s/instructors' % project, json.dumps([ ]),
                         headers = AdministratorHeaders()).raise_for_status()
            requests.put(URL + '/education/api/projects/%s/policy' % project, json.dumps('hidden'),
                         headers = AdministratorHeaders()).raise_for_status()

            CheckGranted(path, headers = AdministratorHeaders())
            CheckForbidden(path, headers = InstructorHeaders())
            CheckForbidden(path, headers = LearnerHeaders())
            CheckForbidden(path, headers = GuestHeaders())

            requests.put(URL + '/education/api/projects/%s/policy' % project, json.dumps('public'),
                         headers = AdministratorHeaders()).raise_for_status()

            CheckGranted(path, headers = AdministratorHeaders())
            CheckGranted(path, headers = InstructorHeaders())
            CheckGranted(path, headers = LearnerHeaders())
            CheckGranted(path, headers = GuestHeaders())

            requests.put(URL + '/education/api/projects/%s/policy' % project, json.dumps('hidden'),
                         headers = AdministratorHeaders()).raise_for_status()

            CheckGranted(path, headers = AdministratorHeaders())
            CheckForbidden(path, headers = InstructorHeaders())
            CheckForbidden(path, headers = LearnerHeaders())
            CheckForbidden(path, headers = GuestHeaders())

            requests.put(URL + '/education/api/projects/%s/instructors' % project, json.dumps([ 'instructor@uclouvain.be' ]),
                         headers = AdministratorHeaders()).raise_for_status()

            CheckGranted(path, headers = AdministratorHeaders())
            CheckGranted(path, headers = InstructorHeaders())
            CheckForbidden(path, headers = LearnerHeaders())
            CheckForbidden(path, headers = GuestHeaders())

            requests.put(URL + '/education/api/projects/%s/learners' % project, json.dumps([ 'learner@uclouvain.be' ]),
                         headers = AdministratorHeaders()).raise_for_status()

            CheckGranted(path, headers = AdministratorHeaders())
            CheckGranted(path, headers = InstructorHeaders())
            CheckForbidden(path, headers = LearnerHeaders())
            CheckForbidden(path, headers = GuestHeaders())

            requests.put(URL + '/education/api/projects/%s/policy' % project, json.dumps('active'),
                         headers = AdministratorHeaders()).raise_for_status()

            CheckGranted(path, headers = AdministratorHeaders())
            CheckGranted(path, headers = InstructorHeaders())
            CheckGranted(path, headers = LearnerHeaders())
            CheckForbidden(path, headers = GuestHeaders())

        def CheckNoAccess(path):
            CheckGranted(path, headers = AdministratorHeaders())
            CheckForbidden(path, headers = InstructorHeaders())
            CheckForbidden(path, headers = LearnerHeaders())
            CheckForbidden(path, headers = GuestHeaders())

        instance = self.create_test_instance_id()
        study = requests.get(URL + '/instances/%s/study' % instance, headers = AdministratorHeaders()).json() ['ID']
        series = requests.get(URL + '/instances/%s/series' % instance, headers = AdministratorHeaders()).json() ['ID']

        project = requests.post(URL + '/education/api/projects', json.dumps({
            'name' : 'Hello',
            'description' : 'World',
        }), headers = AdministratorHeaders()).json() ['id']

        CheckNoAccess('/studies/%s/archive' % study)
        CheckNoAccess('/series/%s/archive' % series)
        CheckNoAccess('/instances/%s/file' % instance)

        body = {
            'resource' : {
                'resource-id' : study,
                'level' : 'Study',
            },
            'project' : project,
        }

        requests.post(URL + '/education/api/link', json.dumps(body), headers = AdministratorHeaders()).raise_for_status()
        CheckPolicyPath('/studies/%s/archive' % study)
        CheckNoAccess('/series/%s/archive' % series)
        CheckNoAccess('/instances/%s/file' % instance)
        requests.post(URL + '/education/api/unlink', json.dumps(body), headers = AdministratorHeaders()).raise_for_status()

        body = {
            'resource' : {
                'resource-id' : series,
                'level' : 'Series',
            },
            'project' : project,
        }

        requests.post(URL + '/education/api/link', json.dumps(body), headers = AdministratorHeaders()).raise_for_status()
        CheckNoAccess('/studies/%s/archive' % study)
        CheckPolicyPath('/series/%s/archive' % series)
        CheckNoAccess('/instances/%s/file' % instance)
        requests.post(URL + '/education/api/unlink', json.dumps(body), headers = AdministratorHeaders()).raise_for_status()

        body = {
            'resource' : {
                'resource-id' : instance,
                'level' : 'Instance',
            },
            'project' : project,
        }

        requests.post(URL + '/education/api/link', json.dumps(body), headers = AdministratorHeaders()).raise_for_status()
        CheckNoAccess('/studies/%s/archive' % study)
        CheckNoAccess('/series/%s/archive' % series)
        CheckPolicyPath('/instances/%s/file' % instance)
        requests.post(URL + '/education/api/unlink', json.dumps(body), headers = AdministratorHeaders()).raise_for_status()

        CheckNoAccess('/studies/%s/archive' % study)
        CheckNoAccess('/series/%s/archive' % series)
        CheckNoAccess('/instances/%s/file' % instance)


    def test_create_free_link(self):
        def Link(project, data):
            requests.post(URL + '/education/api/link', json.dumps({
                'data' : data,
                'project' : project,
            }), headers = AdministratorHeaders()).raise_for_status()

        def CheckNoResource(project):
            lst = requests.get(URL + '/education/api/user-projects', headers = AdministratorHeaders()).json()
            self.assertEqual(0, len(lst['projects'][project]['resources']))

        def CheckHasResource(project, level, resource):
            lst = requests.get(URL + '/education/api/user-projects', headers = AdministratorHeaders()).json()
            resources = lst['projects'][project]['resources']
            self.assertEqual(1, len(resources))
            self.assertEqual(level, resources[0]['level'])
            self.assertEqual(resource, resources[0]['resource-id'])
            return resources[0]

        def Unlink(project):
            lst = requests.get(URL + '/education/api/user-projects', headers = AdministratorHeaders()).json()
            resources = lst['projects'][project]['resources']
            self.assertEqual(1, len(resources))
            requests.post(URL + '/education/api/unlink', json.dumps({
                'resource' : resources[0],
                'project' : project,
            }), headers = AdministratorHeaders()).raise_for_status()

            CheckNoResource(project)

        instance = self.create_test_instance_id()
        tags = requests.get(URL + '/instances/%s/tags?short' % instance, headers = AdministratorHeaders()).json()
        study = requests.get(URL + '/instances/%s/study' % instance, headers = AdministratorHeaders()).json() ['ID']
        series = requests.get(URL + '/instances/%s/series' % instance, headers = AdministratorHeaders()).json() ['ID']

        project = requests.post(URL + '/education/api/projects', json.dumps({
            'name' : 'Hello',
            'description' : 'World',
        }), headers = AdministratorHeaders()).json() ['id']

        CheckNoResource(project)

        Link(project, study)
        resource = CheckHasResource(project, 'Study', study)
        self.assertEqual('TEST - MY^STUDY', resource['title'])
        self.assertEqual([ project ], resource['projects'])
        self.assertEqual(tags['0020,000d'], resource['study-instance-uid'])
        self.assertEqual('', resource['series-instance-uid'])
        self.assertEqual('', resource['sop-instance-uid'])
        self.assertEqual('../api/preview-study/%s' % study, resource['preview_url'])
        Unlink(project)

        Link(project, series)
        resource = CheckHasResource(project, 'Series', series)
        self.assertEqual('TEST - MY^STUDY', resource['title'])
        self.assertEqual([ project ], resource['projects'])
        self.assertEqual(tags['0020,000d'], resource['study-instance-uid'])
        self.assertEqual(tags['0020,000e'], resource['series-instance-uid'])
        self.assertEqual('', resource['sop-instance-uid'])
        self.assertEqual('../api/preview-series/%s' % series, resource['preview_url'])
        Unlink(project)

        Link(project, instance)
        resource = CheckHasResource(project, 'Instance', instance)
        self.assertEqual('TEST - MY^STUDY', resource['title'])
        self.assertEqual([ project ], resource['projects'])
        self.assertEqual(tags['0020,000d'], resource['study-instance-uid'])
        self.assertEqual(tags['0020,000e'], resource['series-instance-uid'])
        self.assertEqual(tags['0008,0018'], resource['sop-instance-uid'])
        self.assertEqual('../api/preview-instance/%s' % instance, resource['preview_url'])
        Unlink(project)

        Link(project, tags['0020,000d'])
        CheckHasResource(project, 'Study', study)
        Unlink(project)

        Link(project, tags['0020,000e'])
        CheckHasResource(project, 'Series', series)
        Unlink(project)

        Link(project, tags['0008,0018'])
        CheckHasResource(project, 'Instance', instance)
        Unlink(project)

        Link(project, 'http://my-public/stone-webviewer/index.html?study=%s' % tags['0020,000d'])
        CheckHasResource(project, 'Study', study)
        Unlink(project)

        Link(project, 'http://my-public/stone-webviewer/index.html?series=%s' % tags['0020,000e'])
        CheckHasResource(project, 'Series', series)
        Unlink(project)

        Link(project, 'http://my-public/volview/index.html?names=[archive.zip]&urls=[../studies/%s/archive]' % study)
        CheckHasResource(project, 'Study', study)
        Unlink(project)

        Link(project, 'http://my-public/volview/index.html?names=[archive.zip]&urls=[../series/%s/archive]' % series)
        CheckHasResource(project, 'Series', series)
        Unlink(project)

        Link(project, 'http://my-public/ohif/viewer?StudyInstanceUIDs=%s' % tags['0020,000d'])
        CheckHasResource(project, 'Study', study)
        Unlink(project)

        Link(project, 'http://my-public/ohif/viewer?hangingprotocolId=mprAnd3DVolumeViewport&StudyInstanceUIDs=%s' % tags['0020,000d'])
        CheckHasResource(project, 'Study', study)
        Unlink(project)

        Link(project, 'http://my-public/ohif/tmtv?StudyInstanceUIDs=%s' % tags['0020,000d'])
        CheckHasResource(project, 'Study', study)
        Unlink(project)

        Link(project, 'http://my-public/ohif/segmentation?StudyInstanceUIDs=%s' % tags['0020,000d'])
        CheckHasResource(project, 'Study', study)
        Unlink(project)

        Link(project, 'http://my-public/ohif/microscopy?StudyInstanceUIDs=%s' % tags['0020,000d'])
        CheckHasResource(project, 'Study', study)
        Unlink(project)

        Link(project, 'http://my-public/wsi/app/viewer.html?series=%s' % series)
        CheckHasResource(project, 'Series', series)
        Unlink(project)

        Link(project, 'http://my-public/wsi/app/viewer.html?instance=%s' % instance)
        CheckHasResource(project, 'Instance', instance)
        Unlink(project)

        Link(project, 'http://my-public/app/explorer.html#study?uuid=%s' % study)
        CheckHasResource(project, 'Study', study)
        Unlink(project)

        Link(project, 'http://my-public/app/explorer.html#series?uuid=%s' % series)
        CheckHasResource(project, 'Series', series)
        Unlink(project)

        Link(project, 'http://my-public/app/explorer.html#instance?uuid=%s' % instance)
        CheckHasResource(project, 'Instance', instance)
        Unlink(project)

        self.assertEqual(400, requests.post(URL + '/education/api/link', json.dumps({
            'data' : 'nope',
            'project' : project,
        }), headers = AdministratorHeaders()).status_code)


try:
    print('\nStarting the tests...')
    unittest.main(argv = [ sys.argv[0] ] + args.options)

finally:
    print('\nDone')
