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
import pprint
import requests
import sys
import unittest


##
## Parse the command-line arguments
##

parser = argparse.ArgumentParser(description = 'Run the integration tests for the WSI Dicomizer.')

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
        'Mail' : 'guest@uclouvain.be'
    }


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


try:
    print('\nStarting the tests...')
    unittest.main(argv = [ sys.argv[0] ] + args.options)

finally:
    print('\nDone')
