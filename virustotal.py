import ConfigParser, json, requests, time, urllib, urllib2

config = ConfigParser.ConfigParser()
config.read('config.cfg')

#Set debug level
if config.get('config','debug') == 'yes': debug = True
else: debug = False

if config.get('config','advanced_debug') == 'yes': advanced_debug = True
else: advanced_debug = False


#Processes Dictionary of unique hashes returning a Dictionary of unique hashes with their VirusTotal results. The "list" input is only used to know where to copy a new file from.
def VirusTotal(list, unique, tanium_handler=False):
	if debug: print ("\n\nMODULE VIRUSTOTAL")
	if debug: print ("FUNCTION virustotal.VirusTotal")
	if debug: print ("  Incuded hashes: " + str(len(list)))
	if debug: print ("  Unique included hashes: " + str(len(unique)))
	new = {}
	updated = {}
	upload = {}
	uploaded = {}
	cached = {}
	not_found = {}
	vt_hashes = {}
	uploaded_count = 0
	
	#Read in VT results from local file cache
	cached = Cache()
	
	#If unique hash is not in cache add it to the new dictionary
	for hash in unique:
		if not hash in cached:
			new[hash] = ''
	
	#Check new hashes against VT
	updated, upload = Check(new)
	
	'''
	vt_upload = config.get('config','upload_files')
	if vt_upload != 'yes':
		if debug: print ("\nFUNCTION virustotal.VirusTotal: Skipping file upload")
	elif len(upload) > 0:
		upload_list = Copy(list, upload, tanium_handler)
		time.sleep(60)
		uploaded_count = Upload(upload_list)
		time.sleep(300)
		uploaded, not_found = Check(upload)
	'''	
	#Combine updated & uploaded Dictionaries then update the local file cache
	updated.update(uploaded)
	UpdateCache(updated)
	
	vt_hashes.update(cached)
	vt_hashes.update(updated)
	vt_stats = {'vt_cache':len(unique)-len(new), 'vt_new':len(new), 'vt_uploaded':uploaded_count}

	return(vt_hashes, vt_stats)

	
#Read in VT results from local file cache
def Cache():
	if debug: print ("\nFUNCTION virustotal.Cache")
	file = open('vt_cache.txt')
	hashes = {}
	for line in file:
		hash = line.rstrip()
		list = hash.split(',')#Hash, Positive, Total, Link
		hashes[list[0]] = [list[1], list[2], list[3], 'no', 'no']
	file.close()
	if debug: print ("  Total hashes in cache: " + str(len(hashes)))
	return(hashes)


#Update local cache file with new VT results	
def UpdateCache(updated):
	if debug: print ("\nFUNCTION virustotal.UpdateCache")
	if debug: print ("  Hashes to add to cache: " + str(len(updated)))
	
	if len(updated)>0:
		file = open('vt_cache.txt', 'a')
		for hash in updated:
			line = hash + ',' + str(updated[hash][0]) + ',' + str(updated[hash][1]) + ',' + updated[hash][2] + '\n'
			file.write(line)
		file.close()
	

#Check new hashes against VT
def Check(new):
	if debug: print ("\nFUNCTION virustotal.Check")
	if debug: print ("  Hashes to check: " + str(len(new)))
	updated = {}
	upload = {}
	
	hashes = []
	for i in new:
		hashes.append(i)
	
	#The VT Public API limits 4 hashes per request and 4 requests per minute so the VT checks need to be spaced accordingly.
	size = len(hashes)
	lower = 0
	upper = 4
	
	while upper < (size+4):
		time.sleep(20)
		THashes = hashes[lower:upper]
		lower += 4
		upper += 4
		hashesString=','.join(THashes)
		apikey = config.get('config','vt_apikey')
		param = {'resource':hashesString,'apikey':apikey,'allinfo': '1'}
		url = config.get('config','vt_url')
		data = urllib.urlencode(param)
		result = urllib2.urlopen(url,data)
		jdata1 =  json.loads(result.read())
		
		#Multiple responses are returned as a list but not a single response. Convert single response to a list of 1.
		jdata = []
		try:
			#Will fail if jdata1 is a list
			if len(str(jdata1['response_code'])) > 0:
				jdata.append(jdata1)
		except:
			jdata = jdata1

		for i in jdata:
			if str(i['response_code']) == '1':
				values = [i['positives'], i['total'], i['permalink'], 'yes', 'no']
				updated[i['md5']] = values
				if advanced_debug: print ('  ' + i['md5'] + ', ' + str(i['positives']))
	
	for i in updated:
		if not i in upload:
			upload[i] = ''
	
	return(updated, upload)