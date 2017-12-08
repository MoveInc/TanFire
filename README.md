# TanFire #
TanFire is a Python script that leverages pyTan and Tanium Index to check the hashes of all new executables in an environment against WildFire and VirusTotal optionally uploading unanalyzed executables to WildFire.


# Script Flow #
- TanFire.main() Calls script's functions
- TanFire.Credentials() Retrieve credentials from the config specified location
- TanFire.Tanium_Connect() Create Tanium handler to use when interacting with the Tanium API
- TanFire.Import_Index() Retrieve list of new hashes in the environment using a Tanium Index Saved Question, process exclusions, and setup list to track hashes with the following fields: computer,file,path,size,md5,sha256,source,wf_malware,wf_new,wf_upload,vt_positive,vt_total,vt_link,vt_new,vt_upload
- wildfire.WildFire() Processes Dictionary of unique hashes returning a Dictionary of unique hashes with their WildFire results. 
  - wildfire.Cache() Read in WF results from local file cache
  - wildfire.Check() Check new hashes against WF
  - wildfire.Copy() Prep list of files to be copied and call Tanium_Copy() 
    - wildfire.Tanium_Copy() Use Tanium copy file package to copy all the new files from a single endpoint to a central share
  - wildfire.Upload() Upload new files to WF
  - wildfire.Check() Recheck recently uploaded files for WF result
  - wildfire.Update_Cache() Update local cache file with new WF results
  - wildfire.Download_Reports() Download WF PDF report of malware hashes  
- virustotal.VirusTotal() Processes Dictionary of unique hashes returning a Dictionary of unique hashes with their VirusTotal results. 
  - virustotal.Cache() Read in VT results from local file cache
  - virustotal.Check() Check new hashes against VT
  - virustotal.Update_Cache() Update local cache file with new VT results
- TanFire.Check() Update list of hashes with results of WildFire and VirusTotal checks
- output.Output() Output results to local csv, Splunk, Slack, and/or Email
  - output.Email() Send statistics and details email


# Notes #
- Authenticated Computers need to have permissions to write to the file share in order for the Copy Files package to work.
- The Index Saved Question only filters for files with the executable magic number (4D5A). Index of course may have its own exclusions set. It is still advisable to appropriately configure exclusions in config.cfg. 
- The username and/or password can either be stored in the config or if they're set to "prompt" the script will prompt for them at runtime. Either will work with 2FA.
- If the Tanium environment uses 2FA there is a Tanium option to enable a secondary password field only useable via the API allowing 2FA for API access from that account to be disabled. Talk to your TAM about configuring.
- This script is designed for Windows Executables. It's worth noting WildFire does support additional file types including Mach-O, DMG, and PKG files for Mac. 


# Authentication #
- To run TanFire without copying and uploading unkown files the Tanium account can use the "Read-Only User" Role.
- To be able to copy and upload unknown files the tanium account needs the "Action User" Role in order to kick off the copy package.
- You can either store the Tanium username in the config or prompt at runtime.
- The Tanium password can be stored in the config, set to prompt at runtime, or be AES encrypted.
- If you choose AES encryption use the createCipherText.py script to create a file with the ciphertext for the password. This file needs to be placed where specified in the config file. Ideally in a separate folder from the script. The AES key is specified and stored in the config file. The IV is based off the SN of the system running the script so the ciphertext won't decode on another system unless an attacker also knows the original SN.
- On the todo list is to add KMS/Vault encryption for the Tanium password. Until that is implemented using an account with the "Action User" roll may not be advisable due to the risk of credential exposure.
- When RBAC support is released an account will be able to be locked down to just the SQ and Copy Package. 


# Requirements #
- The script is run from a Windows box with Python 2.x and a local SMB file share that allows AD Authenticated Computers to write to it.
- Tanium Incident Response solution.
- The "Copy Tools - Copy Files to Central Location" Tanium Package requires importing the "Copy Tools" Solution which is part of Tanium Incident Response. The "Distribute Copy Tools" package has to be deployed to endpoints before the copy package can be used.
- Tanium Index deployed which is part of the Incident Response Solution.
- pyTan. Minimum version 2.1.9.1 which properly ignores SeparatorParameters. https://github.com/tanium/pytan.
- Import Sensor "SENSOR Index Query File Hash Recently Changed with Path and Size.xml". This sensor is a copy of the "Index Query File Hash Recently Changed" sensor but also returns the Path and File Size.
- Import Saved Question "SQ New-Executables.xml". This Saved Question should be configured to run at a regular interval. This allows TanFire to retrieve an immediate response when querying for new executables. 
- Palo Alto Networks WildFire API Key (Paid): https://www.paloaltonetworks.com/documentation/71/wildfire/wf_api/get-started-with-the-wildfire-api/get-your-api-key
- VirusTotal Public API key (Free): https://www.virustotal.com/en/documentation/public-api/
- If Splunk output is used then the splunk_http_event_collector module is needed along with a collector key. https://github.com/georgestarcher/Splunk-Class-httpevent/blob/master/splunk_http_event_collector.py
- If Slack output is used then a Slack Token is needed. https://get.slack.help/hc/en-us/articles/215770388-Create-and-regenerate-API-tokens
- If Email output is used then the smtplib and email modules are needed
- If using AES pycrypto is required: https://pypi.python.org/pypi/pycrypto
  - pycrypto isn't compiled by default due to export restrictions. You can either compile it yourself or use easy_install to install a version compiled by someone else
  - easy_install http://www.voidspace.org.uk/python/pycrypto-2.6.1/pycrypto-2.6.1.win32-py2.7.exe
  - List of additional easy_install link options: http://www.voidspace.org.uk/python/pycrypto-2.6.1/
	
	
# Todo #
- Run in AWS
- Encrypt Password using KMS/Vault
- Option to upload new files to VirusTotal
- Import hashes from running processes
- Package to upload unknown files directly from clients rather than copying them centrally first


# License #
Licensed under the [MIT License](https://opensource.org/licenses/mit-license.php)

Copyright 2017 Move, Inc

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


# Author #
[Jason Javier](https://github.com/JJavier16)
