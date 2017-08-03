__title__       = 'TanFire'
__version__     = 'May 15, 2017'
__author__      = 'Jason Javier'
__description__ = 'TanFire is a Python script that leverages pyTan and Tanium Index to check the hashes of all new executables in an environment against WildFire and VirusTotal optionally uploading unanalyzed executables to WildFire.'

import ConfigParser, requests
import os, sys, pprint, threading, datetime, getpass, shutil
import wildfire, virustotal, output
from subprocess import check_output

config = ConfigParser.ConfigParser()
config.read('config.cfg')
environment = config.get('config','tanium_environment')

#Import pyTan
pytan_path = config.get('config','pytan_path')
sys.path.append(os.path.expanduser(pytan_path))
import pytan

if config.get(environment,'password_option') == 'aes':	
	from Crypto.Cipher import AES
	#https://pypi.python.org/pypi/pycrypto
	#pycrypto isn't compiled by default due to export restrictions. You can either compile it yourself or use easy_install to install a version compiled by someone else
	#Run the following command: "easy_install http://www.voidspace.org.uk/python/pycrypto-2.6.1/pycrypto-2.6.1.win32-py2.7.exe"
	#List of additional easy_install link options: http://www.voidspace.org.uk/python/pycrypto-2.6.1/

#Set debug level
if config.get('config','debug') == 'yes': debug = True
else: debug = False

if config.get('config','advanced_debug') == 'yes': advancedDebug = True
else: advancedDebug = False

if debug: print ("\n\n\n-----------------------------------TAN-FIRE-----------------------------------------")
if debug: print ("\nTanium Environment: " + environment)


def main():
	if debug: print ("\nMODULE TANFIRE")
	if debug: print ("FUNCTION main")
	
	stats = {'computers_total':0, 'computers_hashes':0, 'total':0, 'excluded':0, 'unique':0, 'wf_cache':0, 'wf_new':0, 'wf_uploaded':0, 'vt_cache':0, 'vt_new':0, 'vt_uploaded':0, 'malware':0}
	hashes_list = []
	hashes_unique = {}
	wf_hashes = {}
	wf_stats = {}
	vt_hashes = {}
	vt_stats = {}
	
	#Connect to Tanium and import list of new hashes in the environment
	user, password = Credentials()
	tanium_handler = Tanium_Connect(user, password)
	hashes_list, hashes_unique, stats = Import_Index(tanium_handler, stats)
	
	
	print 'computers total: '  + str(stats['computers_total'])
	print 'computers hashes: ' + str(stats['computers_hashes'])
	print 'hashes total: '     + str(stats['total'])
	print 'hashes excluded: '  + str(stats['excluded'])
	print 'hashes unique: '    + str(stats['unique'])

	
	#Check dictionary of all the unique hashes with WildFire cache, directly, and upload if necessary.
	if config.get('config','wildfire') == 'yes':
		wf_hashes, wf_stats = wildfire.WildFire(hashes_list, hashes_unique, tanium_handler)
		stats.update(wf_stats)
	
	#Check dictionary of all the unique hashes with VirusTotal cache and directly if necessary.
	if config.get('config','virustotal') == 'yes':
		vt_hashes, vt_stats = virustotal.VirusTotal(hashes_list, hashes_unique)
		stats.update(vt_stats)
	
	#Update list of hashes with results of WildFire and VirusTotal checks
	hashes_list = Check(hashes_list, wf_hashes, vt_hashes)
	
	#Output results
	output.Output(hashes_list, stats)
	
	if debug: print ("\n----------------------------------END----------------------------------------------\n\n\n")


#Retrieve credentials from the config specified location	
def Credentials():
	if debug: print ("\nFUNCTION Credentials")
	
	username=config.get(environment,'username')
	if username ==  "prompt":		
		username = raw_input("username: ")
	
	password_option = config.get(environment,'password_option')
	if debug: print ("  Password option: " + str(password_option))
	
	if password_option == 'aes':
		#Retrieve ciphertext
		ciphertext_path = config.get(environment,'ciphertext_path')
		ciphertext_file = open(ciphertext_path, 'r')
		ciphertext_content = ciphertext_file.read()
		ciphertext_file.close()
		list = ciphertext_content.split('b2')
		length = list[0]
		ciphertext = list[1]
		
		#Decrypt ciphertext using key from config file and IV
		#Use last 8 characters of the SN for the IV to limit decryption to the same box that created the original ciphertext
		output = check_output("wmic bios get serialnumber", shell=False)
		SN = output.splitlines()[2].strip()
		iv = SN[-8:] + SN[-8:][::-1]
		key = config.get(environment,'aes_key')
		obj = AES.new(key, AES.MODE_CBC, iv)
		clearMessage = obj.decrypt(ciphertext)
		#Padding: http://stackoverflow.com/questions/14179784/python-encrypting-with-pycrypto-aes
		password = clearMessage[:-int(length)]		
	elif password_option == 'config':
		password = config.get(environment,'password')
	elif password_option == 'kms':
		print ("  AWS KMS future feature")
	else:
		password = getpass.getpass()
		
	return(username, password)
	

#Create Tanium handler to use when interacting with the Tanium API	
def Tanium_Connect(user, passw):
	if debug: print ("\nFUNCTION Tanium_Connect")
	
	#Retrieve Tanium Environment configuration and setup handler
	#try:
	handler = pytan.Handler(
	username = user,
	password = passw,
	host = config.get(environment,'host'),
	port = config.get(environment,'port'),
	loglevel = int(config.get(environment,'log_level')),
	debugformat = config.get(environment,'debug_format'),
	record_all_requests = config.get(environment,'record_all_requests'),
	debug = config.getboolean(environment,'print_debug')
	)
	#except:
		#if debug: print ("\nTanium_Connect FAILED")
		
	return(handler)

	
#Retrieve list of new executable hashs from Tanium	
def Import_Index(handler, stats):
	if debug: print ("\nFUNCTION Import_Index")
	
	#Fields Imported
	#Computer Name,File Name,MD5,Path,SHA1,SHA256,Size
	#New Fields stored in hashes_list[]
	#computer,file,path,size,md5,sha256,source,wf_malware,wf_new,wf_upload,vt_positive,vt_total,vt_link,vt_new,vt_upload
	#List
	#0 computer
	#1 file
	#2 path
	#3 size
	#4 md5
	#5 sha256
	#6 source
	#7 wf_malware
	#8 wf_new
	#9 wf_upload
	#10 vt_positive
	#11 vt_total
	#12 vt_link
	#13 vt_new
	#14 vt_upload
	
	hashes_list = []
	computers_total = {}
	computers_hashes = {}
	hashes_unique = {}
	kwargs = {}
	saved_question = config.get('config','saved_question')
	#Get Computer Name and Index Query File Hash Recently Changed with Path and Size[*, *, *, *, *, *, 4D5A*, 24, 10, 1] from all machines with Is Windows = "true"
	kwargs["qtype"] = u'saved'
	kwargs["name"] = saved_question
	response = handler.ask(**kwargs)

	# call the export_obj() method to convert response to CSV and store it in out
	if response['question_results']:
		export_kwargs = {}
		export_kwargs['obj'] = response['question_results']
		export_kwargs['export_format'] = 'csv'
		export_kwargs["expand_grouped_columns"] = True
		out = handler.export_obj(**export_kwargs)

		# trim the output if it is more than 10 lines long
		'''
		if len(out.splitlines()) > 10:
			hashes = out.split('\n')[0:10]
		else:
			hashes = out.split('\n')		
		'''
		hashes = out.split('\n')		
			
	#Remove output header and trailing entry
	hashes.pop(0)
	hashes.pop()
	
	#Record number of new hashes reported by Tanium
	stats['total'] = len(hashes)
	
	max_size = int(config.get('config','wf_size'))
	exclude_path = config.get('config','path_exclusion')
	exclude_name = config.get('config','name_exclusion')	
	
	output_excluded = config.get('config','output_excluded')
	if output_excluded == 'yes':
		now = datetime.datetime.now()
		timestamp = str(now.year) + '-' + '{:02d}'.format(now.month) + '-' + '{:02d}'.format(now.day) + ' ' + str(now.hour) + ':' + str(now.minute)
		excluded_file = open('excluded.csv', 'a')

	#Cycle through csv output removing exclusions and populating list of hashes to be checked
	for hash in hashes:
		try:
			list = hash.split(',')
			computer = list[0]
			file = list[1]
			md5 = list[2]
			path = list[3]
			sha256 = list[5]
			size = list[6].rstrip()
			
			if not computer in computers_total:
				computers_total[computer] = ''
			
			#Files excluded from analysis
			include = True
			if (file == "No Matches Found" or "Error: " in file or "[no results]" in file): #Tanium did not return any matches for the endpoint
				include = False
			
			#Exclude files larger than the max size
			if include and int(size) > max_size:
				include = False
				if advancedDebug: print ("  Size excluded: " + path + '\\' + file + ", " + size)
				
			#Parse list of strings that if found in the path will exclude the file
			if include and len(exclude_name) > 0:		
				excludeList = exclude_path.split(',')
				for exclude in excludeList:
					if exclude in path:
						include = False
						if advancedDebug: print ("  Path excluded: " + path + '\\' + file)
						break		
						
			#Parse list of strings that if found in the filename will exclude the file	
			if include and len(exclude_name) > 0:				
				excludeList = exclude_name.split(',')				
				for exclude in excludeList:
					if exclude in file:
						include = False
						if advancedDebug: print ("  Name excluded: " + path + '\\' + file)
						break
				
			if include:
				new_list = [computer,file,path,size,md5,sha256,'index','','','','','','','','']
				hashes_list.append(new_list)
				if not md5 in hashes_unique:
					hashes_unique[md5] = ''
				if not computer in computers_hashes:
					computers_hashes[computer] = ''
			else:
				#Count excluded hashes
				stats['excluded'] += 1

		except:
			if debug: 
				print ("Hash in importHashList function failed")
				print (hash)
				print (list)
				print ("File: " + file)
				print ("Path: " + path)
				print ("Size: " + str(size))
		
		if include == False and output_excluded == 'yes':
			line = timestamp + ',' + computer + ',' + path + ',' + file + ',' + md5 + ',' + str(size) + '\n'
			excluded_file.write(line)	
	
	stats['unique'] = len(hashes_unique)
	stats['computers_total'] = len(computers_total)
	stats['computers_hashes'] = len(computers_hashes)
	if output_excluded == 'yes':		
		excluded_file.close()
	if debug:
		print("  Total hashes: " + str(stats['total']))
		print("  Excluded: " + str(stats['excluded']))
		print("  Unique: " + str(stats['unique']))
		
	return(hashes_list, hashes_unique, stats)
	

#Update list of hashes with results of WildFire and VirusTotal checks	
def Check(hashes_list, wf_hashes, vt_hashes):
	if debug: print ("\nFUNCTION Check")
	
	x = 0
	while x < len(hashes_list):
		hash = hashes_list[x][4]
		wf_malware = 'not found'
		wf_new = 'yes'
		wf_upload = ''
		vt_positive = '0'
		vt_total = '0'
		vt_link = ''
		vt_new = 'yes'
		vt_upload = ''
		
		if hash in wf_hashes:
			wf_malware  = wf_hashes[hash][0]
			wf_new      = wf_hashes[hash][1]
			wf_upload   = wf_hashes[hash][2]
		if hash in vt_hashes:
			vt_positive = vt_hashes[hash][0]
			vt_total    = vt_hashes[hash][1]
			vt_link     = vt_hashes[hash][2]
			vt_new      = vt_hashes[hash][3]
			vt_upload   = vt_hashes[hash][4]

		hashes_list[x][7] = wf_malware
		hashes_list[x][8] = wf_new
		hashes_list[x][9] = wf_upload
		hashes_list[x][10] = vt_positive
		hashes_list[x][11] = vt_total
		hashes_list[x][12] = vt_link
		hashes_list[x][13] = vt_new
		hashes_list[x][14] = vt_upload
		x += 1
			
	return(hashes_list)

	
if __name__ == "__main__":
	main()
	