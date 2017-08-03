import ConfigParser, urllib, urllib2, time, datetime, threading, os, requests
import xml.etree.ElementTree as ET

config = ConfigParser.ConfigParser()
config.read('config.cfg')

#Set debug level
if config.get('config','debug') == 'yes': debug = True
else: debug = False

if config.get('config','advanced_debug') == 'yes': advancedDebug = True
else: advancedDebug = False


#Processes Dictionary of unique hashes returning a Dictionary of unique hashes with their WildFire results. The "list" input is only used to know where to copy a new file from.
def WildFire(list, unique, tanium_handler):
	if debug: print ("\n\nMODULE WILDFIRE")
	if debug: print ("FUNCTION wildfire.WildFire")
	if debug: print ("  Incuded hashes: " + str(len(list)))
	if debug: print ("  Unique included hashes: " + str(len(unique)))
	new = {}
	updated = {}
	upload = {}
	uploaded = {}
	cached = {}
	not_found = {}
	wf_hashes = {}
	uploaded_count = 0
	
	#Read in WF results from local file cache
	cached = Cache()
	
	#If unique hash is not in cache add it to the new dictionary
	for hash in unique:
		if not hash in cached:
			new[hash] = ''
	
	#Check new hashes against WF
	updated, upload = Check(new, 'no')
	
	wf_upload = config.get('config','wf_upload')
	if wf_upload != 'yes':
		if debug: print ("\nFUNCTION wildfire.WildFire: Skipping file upload")
	elif len(upload) > 0:
		upload_list = Copy(list, upload, tanium_handler)
		time.sleep(60)
		uploaded_count = Upload(upload_list)
		wf_wait_time = float(config.get('config','wf_wait_time'))
		if debug: print ("\nFUNCTION wildfire.WildFire: Sleeping " + str(wf_wait_time) + " seconds.")
		time.sleep(wf_wait_time)
		uploaded, not_found = Check(upload, 'yes')
	
	#Combine updated & uploaded Dictionaries then update the local file cache
	updated.update(uploaded)
	Update_Cache(updated)
	
	#Combine cached and updated Dictionaries into wf_hashes and compute stats
	wf_hashes.update(cached)
	wf_hashes.update(updated)
	wf_stats = {'wf_cache':len(unique)-len(new), 'wf_new':len(new), 'wf_uploaded':uploaded_count}
	
	#Download malware reports
	Download_Reports(wf_hashes)
	
	return(wf_hashes, wf_stats)

	
#Read in WF results from local file cache
def Cache():
	if debug: print ("\nFUNCTION wildfire.Cache")
	file = open('wf_cache.txt')
	hashes = {}
	for line in file:
		hash = line.rstrip()
		list = hash.split(',')#Hash, Malware Status
		hashes[list[0]] = [list[1], 'no', 'no']
	file.close()
	if debug: print ("  Total hashes in cache: " + str(len(hashes)))
	return(hashes)


#Update local cache file with new WF results	
def Update_Cache(updated):
	if debug: print ("\nFUNCTION wildfire.UpdateCache")
	if debug: print ("  Hashes to add to cache: " + str(len(updated)))
	
	if len(updated)>0:
		file = open('wf_cache.txt', 'a')
		for hash in updated:
			malware = updated[hash][0]
			if (malware == 'yes' or malware == 'no' or malware == 'grayware'):
				line = hash + ',' + malware + '\n'
				file.write(line)
		file.close()
	

#Check new hashes against WF
def Check(new, wf_upload):
	if debug: print ("\nFUNCTION wildfire.Check")
	if debug: print ("  Hashes to check: " + str(len(new)))
	updated = {}
	upload = {}
	for hash in new:
		#Sample File: https://wildfire.paloaltonetworks.com/publicapi/test/pe
		#malware no: 3ee766cf1827c5afa1ac3cccdd29d629
		#malware yes: 2c4bb9f9cf82f797eba0e2cf26fc5275
		#grayware: 455d55000d14b5cdd9e7e6773887a24b
		#hash not found: 65ea57712340c09b1b0c427b4848ae05
		
		try:
			time.sleep(1)
			malware = ''
			apikey = config.get('config','wf_apikey')
			url = config.get('config','wf_url')
			values = {'hash' : hash,
						  'format' : 'xml',
						  'apikey' : apikey }	
			data = urllib.urlencode(values)
			req = urllib2.Request(url, data)
			response = urllib2.urlopen(req)
			results = response.read()
			root = ET.fromstring(results)
			#Return malware status from XML
			malware = root[1][0].text
			updated[hash] = [malware, 'yes', wf_upload]
		except (urllib2.HTTPError) as malware:
			upload[hash] = 'not found'
			
		if advancedDebug: print ('  ' + hash + ', ' + str(malware))

	return(updated, upload)
	

#Copy files from source systems to central share. Share needs to be writable by Authenticated Computers.	
def Copy(list, upload, tanium_handler):
	if debug: print("\nFUNCTION wildfire.Copy")
	if debug: print("  Files to copy: " + str(len(upload)))
	
	upload_list = []
	unique = {}
	for i in list:
		hash = i[4]
		if hash in upload:
			if not hash in unique:
				unique[hash] = ''
				upload_list.append(i)

	length = len(upload_list)
	x = 0
	threads = []
	
	while x < length:
		try:
			file = upload_list[x]
			endpoint = file[0]
			path = file[2] +  "\\" + file[1]
			
			#Check if list will be out of bounds
			if x+1 < length:
				next_endpoint = upload_list[x+1][0]
				
				#If the next entry is for the same Endpoint append the file path so only one copy file package action is run per endpoint. 
				while endpoint == next_endpoint and x+1 < length:
					x += 1
					file = upload_list[x]
					add_path = file[2] +  "\\" + file[1]
					path += '\,' + add_path
					if x+1 < length:
						next_endpoint = upload_list[x+1][0]
			
			#Use threading to call copy file package so they can be run in paralell due to the Tanium targeting question taking 2 minuets to complete. https://pymotw.com/2/threading/
			t = threading.Thread(target=Tanium_Copy, args=(tanium_handler,endpoint,path))
			t.setDaemon(True)
			threads.append(t)
			time.sleep(5)
			t.start()
			x+=1
		except:
			print ("wildfire.Copy function FAILED")
	return(upload_list)

#Execute Tanium's Copy File package			
def Tanium_Copy(handler,endpoint,path):
	if debug: print ("\nFUNCTION Tanium_Copy")
	
	try: 	
		if debug: print ('  ' + endpoint + ': ' + path)
		share_name = config.get('config','share_name')		
		kwargs = {}
		kwargs["run"] = True
		kwargs["action_filters"] = u'Computer Name, that contains:' + endpoint
		kwargs["package"] = u'Copy Tools - Copy Files to Central Location{$1=SMB,$2=' + share_name + ',$3=0,$4=0,$5=' + path + ',$6=No,$7=0,$8=files}'
		
		#This will take 2 minutes for tanium to complete the question
		handler.deploy_action(**kwargs)
		#response = handler.deploy_action(**kwargs)
		
		if debug: print ("\nFUNCTION copyFileTanium END " + endpoint)
			
	except:
		print ("wildfire.Tanium_Copy function FAILED")
	
#Upload files for analysis to WildFire			
def Upload(upload_list):
	if debug: print ("\nFUNCTION wildfire.upload")
	if debug: print ("  Files to upload: " + str(len(upload_list)))
	
	uploaded_count = 0
	url = config.get('config','wf_submit')
	now = datetime.datetime.now()
	apikey = config.get('config','wf_apikey')
	max_size = int(config.get('config','wf_size'))
	local_share_path = config.get('config','local_share_path')
	
	for file in upload_list:
		try: 
			path = file[2] +  "\\" + file[1]
			computer = file[0]
			name = computer.split('.', 1)[0]
			folder = str(now.year) + '-' + '{:02d}'.format(now.month) + '-' + '{:02d}'.format(now.day) + '-' + name
			
			path = local_share_path + "\\" + folder + path[2:]
			path = path.replace("\\\\","\\")
			
			#Verify the file exists and is less than the max size before uploading
			exists = os.path.isfile(path)
			size = os.path.getsize(path) < max_size
			
			if(exists and size):
				if advancedDebug: print "Uploading " + computer + ": " + path + " - " + file[2]
				files = {'file': open(path, 'rb')}
				time.sleep(3)
				r = requests.post(url, files=files, data={'apikey':apikey})		
				#Count hashes of files uploaded to WildFire
				uploaded_count += 1

				if debug: 
					print (path)
					print (file[2]) #Hash
					print (r)
		except:
			print ("wildfire.Upload function FAILED for " + computer + ": " + path)
	return(uploaded_count)

	
#Download WildFire PDF reports for all malware hashes
def	Download_Reports(wf_hashes):
	if debug: print ("\nFUNCTION wildfire.Download_Reports")
	apikey = config.get('config','wf_apikey')
	url = config.get('config','wf_url')
	report_count = 0
	
	for hash in wf_hashes:
		try: 
			md5 = hash
			wf_malware = wf_hashes[md5][0]
			filename = md5 + '.pdf'
			exists = os.path.isfile('reports\\' + filename)
			
			if wf_malware == 'yes' and not exists:
				values = {'hash' : md5,
						  'format' : 'pdf',
						  'apikey' : apikey }
				data = urllib.urlencode(values)
				req = urllib2.Request(url, data)
				response = urllib2.urlopen(req)
				CHUNK = 16 * 1024
				with open('reports\\' + filename, 'wb') as f:
					while True:
						chunk = response.read(CHUNK)
						if not chunk:
							break
						f.write(chunk)
				report_count += 1			
		except:
			print ("  Download_Reports failed for: " + md5)
	
	if debug: print ("  Malware reports downloaded: " + str(report_count))