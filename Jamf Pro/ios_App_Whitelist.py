#!/usr/bin/python

####################################################################################################
#
# Copyright (c) 2015, JAMF Software, LLC.  All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are met:
#               * Redistributions of source code must retain the above copyright
#                 notice, this list of conditions and the following disclaimer.
#               * Redistributions in binary form must reproduce the above copyright
#                 notice, this list of conditions and the following disclaimer in the
#                 documentation and/or other materials provided with the distribution.
#               * Neither the name of the JAMF Software, LLC nor the
#                 names of its contributors may be used to endorse or promote products
#                 derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY JAMF SOFTWARE, LLC "AS IS" AND ANY
#       EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#       WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#       DISCLAIMED. IN NO EVENT SHALL JAMF SOFTWARE, LLC BE LIABLE FOR ANY
#       DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#       (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#       LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#       ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#       SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#   Author: Robert Haake
#   Last Modified: 03/11/2016
#   Version: 1.0 Beta 1
#
#   Description:  This script will generate a profile that contains an app usage restriction with
#   only app catalog apps
#
#   Enter JSS URL as https://yourjssurl.com:8443
#
#   Usage: python app-usage-for-app-catalog.py
#
####################################################################################################

import json
import httplib
import urllib2
import socket
import ssl
import getpass
import base64
import logging
import uuid
import plistlib
import xml.etree.cElementTree as etree
import sys


# Force TLS since the JSS now requires TLS+ due to the POODLE vulnerability
# Forcing TLS1 generated an ssl error. Removing the relevant code restored normal operation. GShea 31/7/18
class TLS1Connection(httplib.HTTPSConnection):
	def __init__(self, host, **kwargs):
		httplib.HTTPSConnection.__init__(self, host, **kwargs)

	def connect(self):
		sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
		if getattr(self, '_tunnel_host', None):
			self.sock = sock
			self._tunnel()

		self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file)
		#self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file, ssl_version=ssl.PROTOCOL_TLSv1)


class TLS1Handler(urllib2.HTTPSHandler):
	def __init__(self):
		urllib2.HTTPSHandler.__init__(self)

	def https_open(self, req):
		return self.do_open(TLS1Connection, req)

class ConfigProfileHelper:

	profile_name = ""
	profile_description = ""
	profile_organization = ""
	profile_uuid = str(uuid.uuid1())

	payloads = []

	def __init__(self,name,description,organization):
		self.profile_name = name
		self.profile_description = description
		self.profile_organization = organization

	def add_restrictions_payload(self,restrictions):
		self.add_payload("com.apple.applicationaccess",restrictions)

	def add_payload(self,payload_type,content):
		payload_uuid = str(uuid.uuid1())
		content['PayloadUUID'] = payload_uuid
		content["PayloadOrganization"] = self.profile_organization
		content["PayloadIdentifier"] = payload_uuid
		content['PayloadDisplayName'] = payload_type
		content['PayloadType'] = payload_type
		content["PayloadVersion"] = 1
		content["PayloadEnabled"] = True

		self.payloads.append(content)



	# Where all the magic happens
	def generate_profile(self):
		profile = {}

		profile['PayloadUUID'] = self.profile_uuid
		profile['PayloadType'] = "Configuration"
		profile['PayloadOrganization'] = self.profile_organization
		profile['PayloadIdentifier'] = self.profile_uuid
		profile['PayloadDisplayName'] = self.profile_name
		profile['PayloadDescription'] = self.profile_description
		profile['PayloadVersion'] = 1
		profile['PayloadEnabled'] = True
		profile['PayloadRemovalDisallowed'] = True

		profile['PayloadContent'] = self.payloads
		formatted_profile = plistlib.writePlistToString(profile)

		return formatted_profile


def main():

	if len(sys.argv) >= 2:
		jss_url = sys.argv[1]
	else:
		jss_url  = raw_input("JSS URL: ")

	if int(len(sys.argv)) >= 3:
		jss_user = sys.argv[2]
	else:
		jss_user = raw_input("JSS Username: ")

	if int(len(sys.argv)) >= 4:
		jss_pass = sys.argv[3]
	else:
		jss_pass = getpass.getpass("JSS Password: ")

	profile_name = raw_input("Configuration Profile Name: ")

	# Hard-coded Description
	profile_description = "Script Generated Profile that allows all apps in app catalog"

	print("Grabbing Organization Name")

	opener = urllib2.build_opener(TLS1Handler())
	request = urllib2.Request(jss_url + "/JSSResource/activationcode")
	request.add_header("Authorization", "Basic " + base64.b64encode('%s:%s' % (jss_user,jss_pass)))
	request.add_header("Accept", "application/json")
	request.get_method = lambda: 'GET'

	try:
		response = opener.open(request)
		api_data = json.load(response)
		profile_organization = api_data['activation_code']['organization_name']
	except urllib2.HTTPError as e:
		logging.error("Bad Call")
		exit()
	except urllib2.URLError as e:
		logging.error("URL Issues: " + str(e))
		exit()

	cph = ConfigProfileHelper(profile_name,profile_description,profile_organization)

	print "Generating App Catalog App Usage"

	restrictions = dict()
	restrictions['whitelistedAppBundleIDs'] = list()
	app_catalog_apps = list()
  
    
	opener = urllib2.build_opener(TLS1Handler())
	request = urllib2.Request(jss_url + "/JSSResource/mobiledeviceapplications")
	request.add_header("Authorization", "Basic " + base64.b64encode('%s:%s' % (jss_user,jss_pass)))
	request.add_header("Accept", "application/json")
	request.get_method = lambda: 'GET'

	try:
		response = opener.open(request)
		api_data = json.load(response)
		for app in api_data['mobile_device_applications']:
			app_catalog_apps.append(app['name'])
			restrictions['whitelistedAppBundleIDs'].append(app['bundle_id'])
	except urllib2.HTTPError as e:
		logging.error("Bad Call")
		exit()
	except urllib2.URLError as e:
		logging.error("URL Issues: " + str(e))
		exit()

	
	appIDs = list(set(restrictions['whitelistedAppBundleIDs']))
	AppleApps = [u'com.apple.AppStore', u'com.apple.store.Jolly', u'com.apple.iBooks', u'com.apple.calculator', u'com.apple.mobilecal', u'com.apple.camera', u'com.apple.clips', u'com.apple.mobiletimer', u'com.apple.compass', u'com.apple.MobileAddressBook', u'com.apple.facetime', u'com.apple.DocumentsApp', u'com.apple.findmy', u'com.apple.Fitness', u'com.apple.mobilegarageband', u'com.apple.Health', u'com.apple.Home', u'com.apple.iCloudDriveApp', u'com.apple.iMovie', u'com.apple.MobileStore', u'com.apple.Keynote', u'com.Apple.Magnifier', u'com.apple.mobilemail', u'com.apple.Maps', u'com.apple.measure', u'com.apple.MobileSMS', u'com.apple.Music', u'com.apple.Music', u'com.apple.mobilenotes', u'com.apple.Numbers', u'com.apple.Pages', u'com.apple.mobilephone', u'com.apple.Photo-Booth', u'com.apple.mobileslideshow', u'com.apple.podcasts', u'com.apple.reminders', u'com.apple.mobilesafari', u'com.apple.Preferences', u'com.apple.shortcuts', u'com.apple.stocks', u'com.apple.Playgrounds', u'com.apple.Translate', u'com.apple.tv', u'com.apple.VoiceMemos', u'com.apple.Passbook', u'com.apple.Bridge', u'com.apple.weather']
	
	
	
	
	newrestrictions = dict()
	newrestrictions['whitelistedAppBundleIDs'] = list(appIDs)
	appIDs.extend(AppleApps)
	

	cph.add_restrictions_payload(newrestrictions)

	config_profile_xml = etree.Element("configuration_profile")
	config_profile_general = etree.Element("general")

	config_profile_general_name = etree.Element("name")
	config_profile_general_name.text = profile_name
	config_profile_general.append(config_profile_general_name)

	config_profile_general_description = etree.Element("description")
	config_profile_general_description.text = profile_description
	config_profile_general.append(config_profile_general_description)

	config_profile_general_uuid = etree.Element("uuid")
	config_profile_general_uuid.text = cph.profile_uuid
	config_profile_general.append(config_profile_general_uuid)

	config_profile_general_payloads = etree.Element("payloads")
	config_profile_general_payloads.text = cph.generate_profile()
	config_profile_general.append(config_profile_general_payloads)

	config_profile_xml.append(config_profile_general)

	xml_data = etree.tostring(config_profile_xml)

	print "Saving Profile..."

	opener = urllib2.build_opener(TLS1Handler())
	request = urllib2.Request(jss_url + "/JSSResource/mobiledeviceconfigurationprofiles/id/0")
	request.add_header("Authorization", "Basic " + base64.b64encode('%s:%s' % (jss_user,jss_pass)))
	request.add_header("Content-Type", "text/xml")
	request.get_method = lambda: 'POST'

	try:
		response = opener.open(request,xml_data)
	except urllib2.HTTPError as e:
		print("Bad Call %s" % e)
		exit()
	except urllib2.URLError as e:
		print("URL Issues: %s" % e)
		exit()

   
	print ""

	print "Apps Added To Allowed Apps App Usage:"
	for app in api_data:
		#print "- %s" % app_catalog_apps
		print "- %s" % restrictions
	print ""

main()