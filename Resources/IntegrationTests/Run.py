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
import json
import pprint
import requests
import sys
import unittest


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
            requests.delete(URL + '/patients/%s' % patient, headers = AdministratorHeaders())

        for project in requests.get(URL + '/education/api/projects', headers = AdministratorHeaders()).json():
            requests.delete(URL + '/education/api/projects/%s' % project['id'], headers = AdministratorHeaders())


    def test_config(self):
        config = requests.get(URL + '/education/api/config', headers = AdministratorHeaders()).json()
        self.assertEqual('admin', config['user']['role'])
        self.assertEqual('admin@uclouvain.be', config['user']['id'])
        self.assertEqual(0, len(config['user']['instructor_of']))
        self.assertEqual(0, len(config['user']['learner_of']))
        self.assertFalse('lti_project_id' in config['user'])

        self.assertEqual('stone', config['default_viewer'])
        self.assertEqual(False, config['has_orthanc_explorer_2'])
        self.assertEqual('education-', config['label_prefix'])
        self.assertEqual('', config['lti_client_id'])
        self.assertEqual(False, config['lti_enabled'])
        self.assertEqual('', config['lti_platform_keys_url'])
        self.assertEqual('', config['lti_platform_redirection_url'])
        self.assertEqual('', config['lti_platform_url'])

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


    def test_logout(self):
        for headers in AnyUserHeaders():
            session = requests.session()
            session.cookies.clear()
            session.cookies.set('orthanc-education-user', 'a', domain = 'localhost.local')
            session.cookies.set('orthanc-education-oidc', 'b', domain = 'localhost.local')
            session.cookies.set('orthanc-education-lti', 'c', domain = 'localhost.local')
            session.cookies.set('orthanc-education-nope', 'd', domain = 'localhost.local')

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


try:
    print('\nStarting the tests...')
    unittest.main(argv = [ sys.argv[0] ] + args.options)

finally:
    print('\nDone')
