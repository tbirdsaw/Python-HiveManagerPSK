#!/usr/bin/python
# Program to Trigger an Action on a WebSite
# For SMCHS's HiveManager
# Created by tbirdsaw
# on 2015/12/11
# Modified
# on 2016/09/15 for SMCHS
progCreateDate = "2015/12/11"
progLastModified = "2016/09/15"
progVersion = "0.23"


#Import our Libraries
import json;
from bs4 import BeautifulSoup;
import requests;

# Disable our SSL Warnings: https://stackoverflow.com/questions/27981545
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import os.path
from datetime import datetime
import ConfigParser
import argparse

# Global Variables
userName = ""
passWord = ""
baseURL = ""
dbgData = False
rawDataFile = ""
cookieFile = ""
urlAppendS1 = ""
urlAppendS2 = ""
urlAppendS3 = ""
ignoreInvalidSSL = False

# Please don't change these! They are required for the CookieJar to work!
cjDataDict = {}
cjData = requests.cookies.RequestsCookieJar()

# Initial Startup
configData = ConfigParser.SafeConfigParser()
parser = argparse.ArgumentParser(description="This program logs into HiveManager and triggers an e-mail for all items under Local Users. It additionally will display the passwords as requested. Options specified on the command line override the config file.")
parser.add_argument("-dm","--debugmode", help="Turn on Debug Messages", action="store_true")
parser.add_argument("-g","--generate-config", help="Generate a config file. Note that this must be edited before using!", action="store_true")
parser.add_argument("-c","--config-file", help="Use the specified config file instead of the default ('./configData.cfg').", default="configData.cfg")
#parser.add_argument("-x","--generate-csv", help="Generate a CSV of all the password data.", action="store_true")
parser.add_argument("-s","--ignore-ssl", help="Ignore SSL errors from untrustworthy certificates.", action="store_true")
parser.add_argument("-ne", "--disable-email", help="Do not trigger sending to emails", action="store_true", default=False)
parser.add_argument("-d", "--display-passwords", help="Display the Users and the Passwords when running", action="store_true", default=False)
parser.add_argument("-sr","--save-last-page", help="Save the last page of data downloaded for analysis.", action="store_true", default=False)

# ConfigParser Generator
def genDefaultConfig():
    configData.add_section('Base Parameters')
    configData.set('Base Parameters', 'username', '<CHANGEME>')
    configData.set('Base Parameters', 'password', '<CHANGEME>')
    configData.set('Base Parameters', 'Base URL', 'https://<CHANGEME>.com')
    configData.set('Base Parameters', 'Cookie File', 'cookies.txt')
    configData.set('Base Parameters', 'Temp Raw Data File', 'rawData.txt')
    configData.set('Base Parameters', 'Debug Mode' , 'false')
    configData.set('Base Parameters', 'Ignore Invalid SSL', 'false')
    configData.add_section('Stage1')
    configData.set('Stage1', 'urlAppend', '/hm/login.action')
    configData.add_section('Stage2')
    configData.set('Stage2', 'urlAppend', '/hm/authenticate.action')
    configData.add_section('Stage3')
    configData.set('Stage3', 'urlAppend', '/hm/localUser.action')

def getConfigData(dataFile):
    if os.path.exists(dataFile):
        configData.read(dataFile)
    else: 
        print "No config file found! Please generate one first!"
        print "Run with '--help' to see available options"
        quit()

#ConfigParser Default Writer
def writeConfig():
    with open('configData.cfg', 'wb') as configfile:
        configData.write(configfile)


def parseConfig():
    global userName    
    userName = configData.get('Base Parameters', 'username')
    global passWord
    passWord = configData.get('Base Parameters', 'password')
    global baseURL
    baseURL = configData.get('Base Parameters', 'Base URL')
    global dbgData
    dbgData = configData.getboolean('Base Parameters', 'Debug Mode')
    if args.debugmode:
        dbgData = args.debugmode
    global rawDataFile
    rawDataFile = configData.get('Base Parameters', 'Temp Raw Data File')
    global cookieFile
    cookieFile = configData.get('Base Parameters', 'Cookie File')
    global urlAppendS1
    urlAppendS1 = configData.get('Stage1','urlappend')
    global urlAppendS2
    urlAppendS2 = configData.get('Stage2', 'urlappend')
    global urlAppendS3
    urlAppendS3 = configData.get('Stage3', 'urlappend')
    global ignoreInvalidSSL
    ignoreInvalidSSL = not configData.getboolean('Base Parameters', 'Ignore Invalid SSL')
    if args.ignore_ssl:
        ignoreInvalidSSL = not args.ignore_ssl


# Authorization Routine!
def authRoutine():
    # Declare these globals in our subroutine, since we use them elsewhere
    global cjData
    global reqData
    #Stage1 Login
    # Build our URL String
    urlLoginPage = baseURL + urlAppendS1

    # Get our request from HiveManager for the cookieData
    if dbgData: print ""
    if dbgData: print "Getting Cookie Data from HiveManager..."
    if dbgData: print "URL: " + urlLoginPage

    reqData = requests.get(urlLoginPage,cookies=cjData,verify=ignoreInvalidSSL)
    # Ensure our cookie session is stored
    cjData = reqData.cookies
    #print requests.utils.dict_from_cookiejar(cjData)
    
    #Stage2 Authentication
    if dbgData: print ""
    if dbgData: print "Logging in... Please wait..."
    # Build our URL String
    urlAuthPage = baseURL + urlAppendS2
    if dbgData: print "URL: " + urlAuthPage

    #print "Printing Inputs"
    hiveData = {}

    # Parse our document to extract all the input "fields" and hidden data
    lDP = BeautifulSoup(reqData.text, 'html.parser')
    for inputs in lDP.find_all('input'):
        # Build a Dict with the data we want
        hiveData[inputs.get('name')] = inputs.get('value')

    # Modify our Post Data with the proper login credentials
    hiveData['userName'] = unicode(userName)
    hiveData['password'] = unicode(passWord)

    #print hiveLoginData


    # Return our login data to the server to see if it lets us in.
    reqData = requests.post(urlAuthPage, data=hiveData, cookies=cjData, verify=ignoreInvalidSSL)
    #cjData = reqData.cookies
    #print requests.utils.dict_from_cookiejar(cjData)    
    



######################################################################

curDate = datetime.now()

print "Aerohive HiveManager PSK E-Mail Trigger"
print "Created for SMCHS on " + progLastModified + " - v" + progVersion
print "Program run on " + curDate.strftime("%Y-%m-%d at %I:%M:%S %p")
print ""



# Get our Parameters from the Config File
args = parser.parse_args()

# See if we specified a config file to be generated. Otherwise, we're going to have to handle errors!
if args.generate_config:
    print "Generating a basic config file, please wait..."
    genDefaultConfig()
    if os.path.exists("configData.cfg"):
        print "Error! Please rename or remove existing config file before generating a new one!"
        quit()
    else:
        writeConfig()
        print "Generated a basic config file. Please edit it before running this program."
        quit()


getConfigData(args.config_file)
parseConfig();


# import our cookies if they exist. Otherwise create a file to save them in JSON format
#print cookieFile

if os.path.isfile(cookieFile):
	if dbgData: print "Found Cookie File!"
	ckFile = open(cookieFile,'r+')
	# Populate our Cookie File
	try:
		requests.utils.cookiejar_from_dict(json.loads(ckFile.read()),cjData)
		ckFile.seek(0)	# We want to rewind to the beginning of the file before writing, just in case.
		#print cjData
	except:
		if dbgData: print "Invalid Cookie Data! Ignoring!"
		ckFile.seek(0)	# We want to rewind to the beginning of the file before writing, just in case.
		requests.utils.cookiejar_from_dict(cjDataDict,cjData)

else:
	if dbgData: print "Cookie File not found. Creating and Opening one!"
	ckFile = open(cookieFile,'w')
	#cjData = requests.utils.cookiejar_from_dict(cjData)
        requests.utils.cookiejar_from_dict(cjDataDict,cjData)


# Attempt to access our UserPage directly first
#Navigate to UserPage
urlUserPage = baseURL + urlAppendS3
if dbgData: print "URL: " + urlUserPage

# Get our Page first...
if dbgData: print "Attempting to get Local User Data page..."
reqData = requests.post(urlUserPage, cookies=cjData, verify=ignoreInvalidSSL)

if "HiveManager Login" in reqData.text :
    if dbgData: print "Authentication needed. Please wait!"
    # Call our Authorization Routine
    authRoutine()
else:
    if dbgData: print "Already Authenticated. Proceeding!"    


# The real parsing of data for our emails
if dbgData: print "Parsing Page for ID Data..."
lDP = BeautifulSoup(reqData.text, 'html.parser')
hiveData = {}

# We need to extract all the form data again, but this time, we're looking for specific data 
for inputs in lDP.find_all('input'):
    # Build a Dict with the data we want
    hiveData[inputs.get('name')] = inputs.get('value')

#print "HiveData: " + str(hiveData)

if dbgData: print "Extracting IDs..."
idTagValues = []
for idTags in lDP.find_all('input'):
#    print idTags.attrs
    if "name" in idTags.attrs :
        if idTags['name'] == "pageIds" :
            if dbgData: print "Found ItemID: " + idTags['value'] 
            idTagValues.append(str(idTags['value']))


if dbgData: print "Modifying Form Data..."
hiveData = {}
hiveData['blnShowOrHidePsk'] = unicode("true")
hiveData['operation'] = unicode("showHidePPSK")
hiveData['id'] = unicode("")
hiveData['tabId'] = unicode("0")
hiveData['forward'] = unicode("")
hiveData['tableId'] = unicode("2503")
hiveData['formChanged'] = unicode("false")
hiveData['paintbrushSource'] = unicode("")
hiveData['paintbrushSourceName'] = unicode("")
hiveData['pageIndex'] = unicode("1")
#hiveData['pageIds'] = unicode("123079939")
#hiveData['pageIds'] = unicode(idTagValues[0])
hiveData['pageSize'] = unicode("15")
hiveData['gotoPage'] = unicode("")




#print "HiveData: " + str(hiveData)



if dbgData: print "Resending Form Data..."
reqData = requests.post(urlUserPage, data=hiveData, cookies=cjData, verify=ignoreInvalidSSL)


# The original form does it weirdly, in that it submits two keys with the same value
# I'm lazy, so we'll have the program just iterate through each one and submit it

if dbgData: print "Emailing all PSKs..."

for PSK in idTagValues:
    #global reqData
    # Note: This was created by observing the page in FireFox
    # It may change at any time!
    if dbgData: print "Generating Form Data..."
    hiveData = {}
    hiveData['blnShowOrHidePsk'] = unicode("true")
    hiveData['operation'] = unicode("email")
    hiveData['id'] = unicode("")
    hiveData['tabId'] = unicode("0")
    hiveData['forward'] = unicode("")
    hiveData['tableId'] = unicode("2503")
    hiveData['formChanged'] = unicode("false")
    hiveData['paintbrushSource'] = unicode("")
    hiveData['paintbrushSourceName'] = unicode("")
    hiveData['pageIndex'] = unicode("1")
    # It doesn't like an array, so don't try it!
    # hiveData['pageIds'] = unicode(PSK)
    # Our single PSK
    hiveData['selectedIds'] = unicode(PSK)
    hiveData['pageSize'] = unicode("15")
    hiveData['gotoPage'] = unicode("")
    
    if dbgData: print "Triggering E-Mail for ID: " + str(PSK)
    if not args.disable_email: reqData = requests.post(urlUserPage, data=hiveData, cookies=cjData, verify=ignoreInvalidSSL)


    
# Just for shits and giggles, let's see if we can extract the passwords

if dbgData: print "Extracting Passwords..."
if dbgData: print "Generating Form Data..."
hiveData = {}
hiveData['blnShowOrHidePsk'] = unicode("true")
hiveData['operation'] = unicode("showHidePPSK")
hiveData['id'] = unicode("")
hiveData['tabId'] = unicode("0")
hiveData['forward'] = unicode("")
hiveData['tableId'] = unicode("2503")
hiveData['formChanged'] = unicode("false")
hiveData['paintbrushSource'] = unicode("")
hiveData['paintbrushSourceName'] = unicode("")
hiveData['pageIndex'] = unicode("1")
# Apparently, not that picky about actually having these in there!
#hiveData['pageIds'] = unicode("123079939")
hiveData['pageSize'] = unicode("15")
hiveData['gotoPage'] = unicode("")

#print "HiveData: " + str(hiveData)

if dbgData: print "Resending Form Data..."
reqData = requests.post(urlUserPage, data=hiveData, cookies=cjData, verify=ignoreInvalidSSL)

if dbgData: print "Parsing for Passwords..."

pwDataRaw = BeautifulSoup(reqData.text, 'html.parser')

pwData = {}
pwData[0] = {}
pwIndex = 0
pwCounter = 0
for tableData in pwDataRaw.find_all('td','list'):
    # Place our Data appropriately
    if pwCounter >= 8 :
        pwIndex+=1
        pwCounter = 0
        pwData[pwIndex] = {}
    # No Case Statement!
    if pwCounter == 0 : pwData[pwIndex]['username'] = tableData.string     # Get the username
    if pwCounter == 1 : pwData[pwIndex]['userType'] = tableData.string   # Get the UserType
    if pwCounter == 2 : pwData[pwIndex]['password'] = tableData.string   # Get the PSK
    if pwCounter == 3 : pwData[pwIndex]['userGroup'] = tableData.string   # Get the UserGroup
    if pwCounter == 4 : pwData[pwIndex]['startTime'] = tableData.string   # Get when this user can start
    if pwCounter == 5 : pwData[pwIndex]['endTime'] = tableData.string   # Get when this user can end
    if pwCounter == 6 : pwData[pwIndex]['emailNotifiers'] = tableData.string   # Get who will be emailed
    if pwCounter == 7 : pwData[pwIndex]['description'] = tableData.string   # Get the description
#    print tableData.string
    pwCounter+=1

#print pwData
# Check to see if there is anything in there first!
if len(pwData[0]) > 0:
    print "There are " + str(len(pwData)) + " password(s)."
    for pwDataDump in range(len(pwData)):
        if args.display_passwords: print "UserID: " + pwData[pwDataDump]["username"] + ", Password: " + pwData[pwDataDump]["password"]
else:
    print "There are no visible passwords, or something went wrong. :("


# Write our CookieData out
if dbgData: print "Saving cookie data for next run..."
ckFile.write(json.dumps(requests.utils.dict_from_cookiejar(cjData)))
ckFile.close()

if dbgData: print "Saving last page of data to text file..."
# Write out our Raw Data for Parsing
if args.save_last_page:
    rawFile = open(rawDataFile,"w")
    rawFile.write(reqData.text)
    rawFile.close()


print "Done!"
# Done!

