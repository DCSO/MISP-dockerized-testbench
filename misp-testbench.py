import unittest
import os
import time
import datetime
import uuid
import requests
import json
import pymisp
import xmlrunner

from requests import HTTPError, ConnectionError, ConnectTimeout
from pymisp import PyMISP, MISPOrganisation, MISPUser, MISPEvent, MISPAttribute, PyMISPError

# Deactivate InsecureRequestWarnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def readInSettings():
    try:
        with open("settings.json", "r") as settings_file:
            data = json.load(settings_file)
            return data
    except (FileNotFoundError, ImportError):
        print ("Error settings file not found or invalid")
        raise RuntimeError

def readInFile(filename):
    try:
        with open(filename, "r") as settings_file:
            data = json.load(settings_file)
            return data
    except (FileNotFoundError, ImportError):
        print ("Error settings file not found or invalid")
        raise RuntimeError

def connectMISP():    
    misp_settings = readInSettings()
    misp_url = misp_settings['url']
    misp_key = misp_settings['authkey']
    if misp_settings['verify_cert'] is "False" or misp_settings['verify_cert'] == "False":
            misp_verifycert = False
    try:
        misp = PyMISP(misp_url, misp_key, misp_verifycert)
        return misp
    except PyMISPError as e:
        print(e)
        return False


class MISPConnection(unittest.TestCase):
# This should always be the first test and if one of it fails the misp platform is not available or an internal error has occured

# POST /users/login HTTP/1.1
#Host: misp.acme.test
#Referer: https://misp.acme.test/users/login
#Content-Type: application/x-www-form-urlencoded
#Content-Length: 366
#Cookie: CAKEPHP=jv5ae63bq30dbh33r75efi4ve1
#Connection: close
#Upgrade-Insecure-Requests: 1
#_method=POST&data%5B_Token%5D%5Bkey%5D=255c3a7793491b18e6a1dc795fc1ee87c3bcbe71015d264a75d6a4b762a726a3a419417df6a351c7d226c834ed0ec12bef1f2928630b96c28107988836c6d0ca&data%5BUser%5D%5Bemail%5D=admin%40admin.test&data%5BUser%5D%5Bpassword%5D=Blafasel123456%21&data%5B_Token%5D%5Bfields%5D=1d46aae96401d29b19f13c05576ad86e051e2802%253A&data%5B_Token%5D%5Bunlocked%5D=

    def test_NginxConnection(self):
        misp_settings = readInSettings()
        misp_verifycert = True
        if misp_settings['verify_cert'] is "False" or misp_settings['verify_cert'] == "False":
            misp_verifycert = False

        r = requests.get(misp_settings['url'], verify=misp_verifycert)
        self.assertIsNot(r.status_code, 502, msg="Nginx works as normal")

    def test_BasicConnection(self):
        misp_settings = readInSettings()
        misp_verifycert = True
        if misp_settings['verify_cert'] is "False" or misp_settings['verify_cert'] == "False":
            misp_verifycert = False

        r = requests.get(misp_settings['url'], verify=misp_verifycert)        
        self.assertIs(r.status_code, 200, msg="MISP is not available or an internal error occured")

class MISPCoreFunctions(unittest.TestCase):
    #Tests if the core functions of MISP like Tags, Objects, Galaxy can be updated correctly and if they work 
    _misp = ""

    def setUp(self):
        self._misp = connectMISP()

    def test_UpdateTaxonomies(self):
        # At Start, there should'nt be a taxonomie
        response = self._misp.get_taxonomies_list()
        #self.assertEqual(len(response['response']), 0)

        # Update taxonomies - if everything is fine MISP respond with "Successfully updated"
        response = self._misp.update_taxonomies()
        self.assertTrue("Successfully updated" in response['message'])

        # Updated list of taxonomies should have more than 10 entries
        response = self._misp.get_taxonomies_list()
        self.assertGreaterEqual(len(response['response']), 10)
        #Maybe add a check for tags here as example tlp:green


    def test_EnableTaxonomies(self):
        list_taxonomies = self._misp.get_taxonomies_list()
        for item in list_taxonomies['response']:
            if 'tlp' in item['Taxonomy']['namespace']:
                response = self._misp.enable_taxonomy(item['Taxonomy']['id'])
                # if the taxonomy was successfully updated MISP responses with 'Taxonomy enabled'
                self.assertTrue("Taxonomy enabled" in response['message'])

                response = self._misp.get_taxonomy_tags_list(item['Taxonomy']['id'])
                pass

    
    def test_UpdateGalaxies(self):
        # At Start, there should'nt be a galaxie
        response = self._misp.get_galaxies()
        #self.assertEqual(len(response['response']), 0)

        # Update galaxies - if everything is fine MISP respond with "Galaxies updated."
        response = self._misp.update_galaxies()
        self.assertTrue("Galaxies updated" in response['message'])

        # Updated list of galaxie should have more than 10 entries
        response = self._misp.get_galaxies()
        self.assertGreaterEqual(len(response['response']), 10)


    def test_UpdateObjects(self):
        # At Start, there should'nt be a taxonomie
        response = self._misp.get_object_templates_list()        
        #self.assertEqual(len(response['response']), 0)

        # Update object templates - if everything is fine MISP respond with the list of object templates
        response = self._misp.update_object_templates()
        self.assertGreaterEqual(len(response['response']), 10)

        # Updated list of objects should have more than 10 entries
        response = self._misp.get_object_templates_list()
        self.assertGreaterEqual(len(response['response']), 10)


class MISPUserManagement(unittest.TestCase):    
    # Create a new user
    # Authenticate with the new user
    _misp = ""

    def setUp(self):
        self._misp = connectMISP()

    def test_GetUserList(self):
        r = self._misp.get_users_list()
        self.assertIsInstance(r, dict, "Response has to be a list of elements")
        self.assertGreater(len(r['response']), 0, "Initial list of orgs must be greater than 0")


    def test_OrgAndUserTest(self):
        """ 
        This test creats new organisations from the org.json file and adds user from the user.json file to it.
        After all organisations and user are created the tests removes them and checks if they are correctly removed
        """
        
        ### Create organisations from org.json file
        list_orgs = self._misp.get_organisations_list()
        self.assertEqual(len(list_orgs['response']), 1, "List of orgs must be 1")

        org_list = readInFile("samples/org.json")        
        tested_keys = ['name', 'description', 'nationality', 'sector', 'uuid', 'contacts']

        for item in org_list:
            response = self._misp.add_organisation(
                name=org_list[item]['name'],
                description=org_list[item]['description'],
                nationality=org_list[item]['nationality'],
                sector=org_list[item]['sector'],
                uuid=org_list[item]['uuid'],
                contacts=org_list[item]['contacts'],
                local=org_list[item]['local']
            )       
            self.assertIsInstance(response, dict, "Response has to be a dict of elements")
            for k in tested_keys:
                self.assertEqual(org_list[item][k], response['Organisation'][k])
            #rof
        #rof 

        list_orgs = self._misp.get_organisations_list()
        self.assertEqual(len(list_orgs['response']), 3, "List of orgs must be 3")

        ### Add new user from the user.json file
        list_user = readInFile("samples/user.json")
        current_org_list = self._misp.get_organisations_list(scope='local')
        for item in list_user:
            for org in current_org_list['response']:
                if org['Organisation']['name'] == list_user[item]['org_id']:
                    response = self._misp.add_user(list_user[item]['email'], org['Organisation']['id'], list_user[item]['role_id'])
                    self.assertIsInstance(response, dict, "Response has to be a dict of elements")
                    self.assertEqual(list_user[item]['email'], response['User']['email'])
                    self.assertEqual(org['Organisation']['id'], response['User']['org_id'])
                    self.assertEqual(list_user[item]['role_id'], response['User']['role_id'])
                    # legnth of regular authkeys is 40 chars or longer
                    self.assertGreaterEqual(len(response['User']['authkey']), 40)

        ### An authentication test could be inserted here

        ### An user change role test coul be inserted here

        ### Remove new user
        response = self._misp.get_users_list()        
        for item in response['response']:
            for user in list_user:
                if item['User']['email'] == list_user[user]['email']:
                    response = self._misp.delete_user(item['User']['id'])
                    self.assertTrue('User deleted' in response['message'])

        response = self._misp.get_users_list()
        self.assertEqual(len(response['response']), 1, "List of user must be 1 (admin user)")

        ### Remove organisations
        org_list = readInFile("samples/org.json")
        response = self._misp.get_organisations_list()
        for item in response['response']:
            for org_item in org_list:
                if item['Organisation']['name'] == org_list[org_item]['name']:
                    response = self._misp.delete_organisation(item['Organisation']['id'])
                    self.assertTrue('Organisation deleted' in response['message'])
                    # Assert is missing here
        
        response = self._misp.get_organisations_list()
        self.assertEqual(len(response['response']), 1, "List of orgs must be 1")

    @unittest.skip("Not yet implemented") 
    def test_ChangeUserRole(self):
        pass

    @unittest.skip("Not yet implemented") 
    def test_AuthWithNewUser(self):
        pass  

    

class MISPEventHandling(unittest.TestCase):
    # Add and remove an event
    # Add and remove attributes from an event
    # Publish the event
    # Add an attachment
    _misp = ""

    def setUp(self):
        self._misp = connectMISP()
    
    def test_CreateSearchRemoveEvents(self):
        """
        This test creats, searches and removes sample events from templates wich can be definied in the event_list.json file.
        """
        file_list = readInFile("samples/event_filelist.json")

        # Create events from samples
        for item in file_list:
            if file_list[item]['active']:
                event = readInFile("samples/" + str(file_list[item]['file_name']))
                sample = event['response'][0]
                response = self._misp.add_event(sample)
            pass
            # Assert is missing here

        for item in file_list:
            if file_list[item]['active']:
                event = readInFile("samples/" + str(file_list[item]['file_name']))
                sample = event['response'][0]
                # if sample is found MISP should respond with the corresponding event
                response = self._misp.search_index(eventinfo=sample['Event']['info'])
                self.assertEqual(sample['Event']['info'], response['response'][0]['info'])
                
                # try to delete the event
                response = self._misp.delete_event(response['response'][0]['id'])
                # if the event was successfully deleted MISP respond with "Event deleted"
                self.assertTrue('Event deleted' in response['message'])
                pass


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
    #unittest.main()
    with open('reports/results.xml', 'wb') as output:
        unittest.main(
            testRunner=xmlrunner.XMLTestRunner(output=output),
            failfast=False, buffer=False, catchbreak=False)