#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import os
import time
import datetime
import uuid
import requests
import json
import pymisp
import xmlrunner
import urllib3
from pymisp.tools import make_binary_objects
from datetime import datetime, timedelta, date
from io import BytesIO
import re
import json
from pathlib import Path
import time
from uuid import uuid4
import sys
import logging

from requests import HTTPError, ConnectionError, ConnectTimeout

try:
    from pymisp import ExpandedPyMISP, MISPEvent, MISPOrganisation, MISPUser, Distribution, ThreatLevel, Analysis, \
        MISPObject, MISPAttribute, MISPSighting, MISPShadowAttribute, MISPTag, MISPSharingGroup, MISPFeed, MISPServer, \
        PyMISPError, MISPServerError
    from pymisp.tools import CSVLoader, DomainIPObject, ASNObject, GenericObjectGenerator
except ImportError:
    if sys.version_info < (3, 6):
        print('This test suite requires Python 3.6+, breaking.')
        sys.exit(0)
    else:
        raise

urllib3.disable_warnings()


def readInSettings():
    try:
        with open("settings.json", "r") as settings_file:
            data = json.load(settings_file)
            return data
    except (FileNotFoundError, ImportError):
        print("Error settings file not found or invalid")
        raise RuntimeError


def readInFile(filename):
    try:
        with open(filename, "r") as settings_file:
            data = json.load(settings_file)
            return data
    except (FileNotFoundError, ImportError):
        print("Error settings file not found or invalid")
        raise RuntimeError


def connectMISP():
    misp_settings = readInSettings()
    misp_url = misp_settings['url']
    misp_key = misp_settings['authkey']
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

    if misp_settings['verify_cert'] is "False" or misp_settings['verify_cert'] == "False":
        misp_verifycert = False
    try:
        misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert, debug=False)
        return misp

    except (PyMISPError, MISPServerError) as e:
        logging.warning("Error: Can not connect to MISP")
        logging.warning(e)
        return False


def cleanUp(misp_instance):
    misp_instance = None


logg_sets = readInSettings()
logg_err = True
if "loglevel" in logg_sets and "log2file" in logg_sets:
    if "True" in logg_sets['log2file']:
        if "debug" in logg_sets['loglevel']:
            logging.basicConfig(filename='logs/test_output.log', filemode='w',
                                format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)
            logg_err = False
        if "info" in logg_sets['loglevel']:
            logging.basicConfig(filename='logs/test_output.log', filemode='w',
                                format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
            logg_err = False
else:
    if "debug" in logg_sets['loglevel']:
        logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)
        logg_err = False
    else:
        logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
        logg_err = False

if logg_err:
    # Switching back to default
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)


class MISPConnection(unittest.TestCase):
    # This should always be the first test and if one of it fails the misp platform is not available or an internal error has occured

    # POST /users/login HTTP/1.1
    # Host: misp.acme.test
    # Referer: https://misp.acme.test/users/login
    # Content-Type: application/x-www-form-urlencoded
    # Content-Length: 366
    # Cookie: CAKEPHP=jv5ae63bq30dbh33r75efi4ve1
    # Connection: close
    # Upgrade-Insecure-Requests: 1
    # _method=POST&data%5B_Token%5D%5Bkey%5D=255c3a7793491b18e6a1dc795fc1ee87c3bcbe71015d264a75d6a4b762a726a3a419417df6a351c7d226c834ed0ec12bef1f2928630b96c28107988836c6d0ca&data%5BUser%5D%5Bemail%5D=admin%40admin.test&data%5BUser%5D%5Bpassword%5D=Blafasel123456%21&data%5B_Token%5D%5Bfields%5D=1d46aae96401d29b19f13c05576ad86e051e2802%253A&data%5B_Token%5D%5Bunlocked%5D=

    def test_NginxConnection(self):
        misp_settings = readInSettings()
        misp_verifycert = True
        if misp_settings['verify_cert'] is "False" or misp_settings['verify_cert'] == "False":
            misp_verifycert = False

        logging.info("Connection - Checking if Nginx is available")
        r = requests.get(misp_settings['url'], verify=misp_verifycert)
        self.assertIsNot(r.status_code, 502, msg="Nginx sent error code 502 - MISP not available")

    def test_BasicConnection(self):
        misp_settings = readInSettings()
        misp_verifycert = True
        if misp_settings['verify_cert'] is "False" or misp_settings['verify_cert'] == "False":
            misp_verifycert = False

        logging.info("Connection - Checking if MISP came up without errors")
        r = requests.get(misp_settings['url'], verify=misp_verifycert)
        self.assertIs(r.status_code, 200, msg="MISP is not available or an internal error occurred")


class MISPCoreFunctions(unittest.TestCase):
    # Tests if the core functions of MISP like Tags, Objects, Galaxy can be updated correctly and if they work
    _misp = ""

    def setUp(self):
        self._misp = connectMISP()

    def test_Taxonomies(self):
        # Update taxonomies - if everything is fine MISP respond with "Successfully updated"
        logging.info("Taxonomies - Check if taxonomies can be updated")
        response = self._misp.update_taxonomies()
        self.assertTrue("Successfully updated" in response['message'] or "up to date" in response['message'],
                        msg="MISP taxonomies can not be updated")

        # Updated list of taxonomies should have more than 10 entries
        logging.info("Taxonomies - Check if there are more then 10 taxonomies available")
        list_taxonomies = self._misp.taxonomies(pythonify=True)
        self.assertGreaterEqual(len(list_taxonomies), 10,
                                msg="MISP responded only with a list of less then 10 available taxonomies - there should be more")

        for item in list_taxonomies:
            if 'tlp' in item['namespace']:
                logging.info("Taxonomies - Check if TLP can be enabled")
                response = self._misp.enable_taxonomy(item['id'])
                # if the taxonomy was successfully updated MISP responses with 'Taxonomy enabled'
                self.assertTrue("Taxonomy enabled" in response['message'], msg="TLP taxonomy could not be enabled")

                logging.info("Taxonomies - Check if TLP taxonomy contains at least 4 tags")
                response = self._misp.enable_taxonomy_tags(item['id'])
                # self.assertTrue("Something" in response['message'])
                response = self._misp.get_taxonomy_tags_list(item['id'])
                # usually the TLP taxonomy has at least 4 tags
                self.assertGreaterEqual(len(response), 4,
                                        msg="TLP taxonomy has less than 4 entries - there should be at least 4")
                pass

    def test_Galaxies(self):
        # At Start, there should'nt be a galaxie
        response = self._misp.get_galaxies()
        # self.assertEqual(len(response['response']), 0)

        # Update galaxies - if everything is fine MISP respond with "Galaxies updated."
        logging.info("Galaxies - Check if galaxies can be updated")
        response = self._misp.update_galaxies()
        self.assertTrue("Galaxies updated" in response['message'], msg="Galaxies could not be updated")

        # Updated list of galaxie should have more than 10 entries
        logging.info("Galaxies - Check if there are at least 10 galaxies")
        response = self._misp.galaxies(pythonify=True)
        self.assertGreaterEqual(len(response), 10,
                                msg="MISP responded only with a list of less then 10 available galaxies - there should be more")

        for item in response:
            if "Threat Actor" in item.name:
                logging.info("Galaxies - Try to get galaxy \"Threat Actor\" by id")
                r = self._misp.get_galaxy(item.id, pythonify=True)
                self.assertTrue("Threat Actor" in r.name, msg="Threat Actor galaxy could not be found")
        pass

    def test_Objects(self):
        # At Start, there should'nt be a taxonomie
        logging.info("Objects - Try update object templates")
        response = self._misp.update_object_templates()

        logging.info("Objects - Checking of MISP responded the object template list and if list has at leas 10 items")
        self.assertIsInstance(response, list, msg="MISP does not responded with a list of objects")
        self.assertGreaterEqual(len(response), 10,
                                msg="MISP responded only with a list of less then 10 available objects - there sould be more")
        pass

    def tearDown(self):
        cleanUp(self._misp)


class MISPUserManagement(unittest.TestCase):
    # Create a new user
    # Authenticate with the new user
    _misp = ""

    def setUp(self):
        self._misp = connectMISP()

    def test_CheckAdminUser(self):
        logging.info("AdminManagement - Check if the first - the admin org - exists")
        response = self._misp.organisations(pythonify=True)
        self.assertGreater(len(response), 0, msg="MISP responded with 0 available organisations - admin org is missing")

        logging.info("AdminManagement - Check if at least 1 user - the admin - user exists")
        response = self._misp.users(pythonify=True)
        self.assertGreater(len(response), 0, "MISP responded with 0 available users - admin user is missing ")

        logging.info("AdminManagement - Check if user has admin rights")
        self.assertTrue(response[0].role_id is '1', msg="The initial admin user has no admin rights")
        pass

    def test_Organisations(self):
        """ 
        This test creats new organisations from the org.json file and adds user from the user.json file to it.
        After all organisations and user are created the tests removes them and checks if they are correctly removed
        """

        ### Create organisations from org.json file

        org_list = readInFile("samples/org.json")
        tested_keys = ['name', 'description', 'nationality', 'sector', 'uuid', 'contacts']

        for item in org_list:
            org = MISPOrganisation()
            org.name = org_list[item]['name']
            org.description = org_list[item]['description']
            org.nationality = org_list[item]['nationality']
            org.sector = org_list[item]['sector']
            org.uuid = org_list[item]['uuid']
            org.contacts = org_list[item]['contacts']
            # org.local = org_list[item]['local']

            logging.info("OrgManagement - try to create organization \"" + org_list[item]['name'] + "\"")
            response = self._misp.add_organisation(org, pythonify=True)

            self.assertTrue(org_list[item]['uuid'] in response.uuid,
                            msg="The created organisation has no or a wrong UUID")
            self.assertTrue(org_list[item]['name'] in response.name,
                            msg="The created organisation has no or a wrong name")
            self.assertTrue(org_list[item]['description'] in response.description,
                            msg="The created organisation has no or a wrong description")
            self.assertTrue(org_list[item]['nationality'] in response.nationality,
                            msg="The created organisation has no or a wrong nationality")
            self.assertTrue(response.local,
                            msg="The created organisation is not a local organisation but should be a local organisation")
            self.assertTrue(org_list[item]['sector'] in response.sector,
                            msg="The created organisation has no or a wrong sector")

        response = self._misp.organisations(scope="local", pythonify=True)
        logging.info("OrgManagement - check if the admin and both test organisations exist")
        self.assertGreaterEqual(len(response), 3,
                                "MISP responded with less then 3 existing organisations - there shold exactly be 3")

        ### Add new user from the user.json file
        list_user = readInFile("samples/user.json")
        users = self._misp.users(pythonify=True)
        for item in list_user:
            for org in response:
                if org.name in list_user[item]['org_id']:
                    logging.info("OrgManagement - try to add user \"" + list_user[item]['email'] + "\"")
                    usr = MISPUser()
                    usr.email = list_user[item]['email']
                    usr.org_id = org.id
                    usr.role_id = list_user[item]['role_id']

                    usr_response = self._misp.add_user(usr, pythonify=True)

                    # legnth of regular authkeys is 40 chars or longer
                    self.assertTrue(usr_response.email in list_user[item]['email'],
                                    msg="The created users has no or a wrong email")
                    self.assertTrue(usr_response.role_id in list_user[item]['role_id'],
                                    msg="The created users has no or a wrong role id")
                    self.assertGreaterEqual(len(usr_response.authkey), 40,
                                            msg="MISP responded with a wrong authkey - should be exactly 40 chars")

        ### An authentication test could be inserted here

        ### An user change role test could be inserted here

        logging.info("OrgManagement - check if all user where created successfully")
        response = self._misp.users(pythonify=True)
        self.assertGreaterEqual(len(response), len(list_user),
                                msg="MISP responded with a wrong number of users - it seems that not all users could be created.")

        for item in response:
            if item.org_id not in '1' or item.id not in '1':
                logging.info("OrgManagement - try to delete user \"" + item.email + "\"")
                usr_response = self._misp.delete_user(item)
                self.assertTrue("User deleted" in usr_response['message'], msg="User could ne be deleted")
                pass

        logging.info("OrgManagement - check if user list now only contains the admin user")
        response = self._misp.users(pythonify=True)
        self.assertEqual(len(response), 1,
                         "MISP responded with a wrong number of users - it seems that not all users could be deleted.")

        ### Remove organisations
        response = self._misp.organisations(pythonify=True)
        for item in response:
            if item.id not in "1":
                logging.info("Try to remove organization: \"" + item.name + "\"")
                org_response = self._misp.delete_organisation(item)
                self.assertTrue('deleted' in org_response['message'],
                                msg="Organisations could not be deleted from MISP")
            pass

        response = self._misp.organisations(pythonify=True)
        logging.info("OrgManagement - check if only admin org exist")
        self.assertEqual(len(response), 1,
                         msg="MISP responded with a wrong number of organisations - it seems that not all organisations could be deleted.")

    @unittest.skip("Not yet implemented")
    def test_ChangeUserRole(self):
        pass

    @unittest.skip("Not yet implemented")
    def test_AuthWithNewUser(self):
        pass

    def tearDown(self):
        cleanUp(self._misp)


class MISPEventHandling(unittest.TestCase):
    # Add and remove an event
    # Add and remove attributes from an event
    # Publish the event
    # Add an attachment
    _misp = ""

    def setUp(self):
        self._misp = connectMISP()

    def tearDown(self):
        cleanUp(self._misp)

    def test_CreateSearchRemoveEvents(self):
        """
        This test creat's, searches and removes sample events from templates which can be defined in the event_list.json file.
        """
        logging.info(
            "EventHandling - This test creat's, searches and removes sample events from templates which can be defined in the event_list.json file.")
        file_list = readInFile("samples/event_filelist.json")

        try:
            # Create events from samples
            logging.info("EventHandling - Try to create MISP events from files")
            for item in file_list:
                if file_list[item]['active']:
                    event = readInFile("samples/" + str(file_list[item]['file_name']))
                    sample = event['response'][0]
                    attr_len1 = len(sample['Event']['Attribute'])
                    obj_len1 = len(sample['Event']['Object'])
                    logging.info("EventHandling - Try to add event with name: " + sample['Event']['info'])
                    response = self._misp.add_event(sample)
                    if 'errors' not in response:
                        attr_len2 = len(response['Event']['Attribute'])
                        obj_len2 = len(response['Event']['Object'])
                        # Skip Test
                        self.assertGreater(attr_len1, 0, "Created event has 0 attributes - there should be at least 1")
                        # self.assertEqual(attr_len1, attr_len2)
                        # self.assertEqual(obj_len1, obj_len2)
                pass

            logging.info("EventHandling - Try to search for specific events on index")
            for item in file_list:
                if file_list[item]['active']:
                    event = readInFile("samples/" + str(file_list[item]['file_name']))
                    sample = event['response'][0]
                    # if sample is found MISP should respond with the corresponding event
                    logging.info("EventHandling - Searching for event: " + sample['Event']['info'])
                    response = self._misp.search_index(eventinfo=sample['Event']['info'], pythonify=True)
                    self.assertEqual(sample['Event']['info'], response[0].info,
                                     msg="MISP responded with an event whose info field does not match the given event info")

                    # try to delete the event
                    logging.info("EventHandling - Try to delete event with ID: " + str(response[0].id) + " from index")
                    response = self._misp.delete_event(response[0].id)
                    # if the event was successfully deleted MISP respond with "Event deleted"
                    self.assertTrue('Event deleted' in response['message'], msg="Given event could not be deleted")

                    pass

        except (MISPServerError, PyMISPError) as e:
            logging.error("EventHandling - Error executing tests")
            logging.error(e)

    @unittest.skip("Not yet implemented")
    def test_ModifyEventAttributes(self):
        pass

    @unittest.skip("Not yet implemented")
    def test_PublishEvents(self):
        pass

    @unittest.skip("Not yet implemented")
    def test_ModifyEventAddAttachment(self):
        pass

    @unittest.skip("Not yet implemented")
    def test_RemoveEvents(self):
        pass


class MISPFeedAndServerHandling(unittest.TestCase):
    # A server has to be added in the menu
    # A full pull job has to be started
    # Monitoring
    #    The pull job can be monitored by the job health itself
    #    The existents of a set of events can be tested
    _misp = ""

    def setUp(self):
        self._misp = connectMISP()

    def test_RetreciveFeedList(self):
        self._misp.get_feed_fields_list()
        # Assert is missing here
        pass

    def test_ActivateFeed(self):
        self._misp.get_feed_fields_list()
        pass

    @unittest.skip("Not yet implemented")
    def test_CacheActiveFeeds(self):
        pass

    @unittest.skip("Not yet implemented")
    def test_DeactivateFeed(self):
        pass

    @unittest.skip("Not yet implemented")
    def test_AddRemoteServer(self):
        pass

    @unittest.skip("Not yet implemented")
    def test_StartPullFromRemoteServer(self):
        pass

    @unittest.skip("Not yet implemented")
    def test_StartPushToRemoteServer(self):
        pass

    @unittest.skip("Not yet implemented")
    def test_removeRemoteServer(self):
        pass


if __name__ == '__main__':
    with open('reports/results.xml', 'wb') as output:
        unittest.main(
            testRunner=xmlrunner.XMLTestRunner(output=output),
            failfast=False, buffer=False, catchbreak=False)
