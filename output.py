import os, datetime, time, ConfigParser, urllib2

#Import additional modules as needed based on set config
config = ConfigParser.ConfigParser()
config.read('config.cfg')
environment = config.get('config','tanium_environment')

if config.get('config','email') == 'yes': 
	import smtplib
	from os.path import basename
	from email.mime.application import MIMEApplication
	from email.mime.multipart import MIMEMultipart
	from email.mime.text import MIMEText
	from email.utils import COMMASPACE, formatdate

if config.get('config','splunk') == 'yes': from splunk_http_event_collector import http_event_collector
#https://github.com/georgestarcher/Splunk-Class-httpevent/blob/master/splunk_http_event_collector.py

#Set debug level
if config.get('config','debug') == 'yes': debug = True
else: debug = False
	
	
#Output results to local csv, Splunk, Slack, and/or Email
def Output(hashes_list, stats):
	if debug: print ("\n\nMODULE OUTPUT")
	if debug: print ("FUNCTION output.Output")
	details = ""
	vt_malware_threshold = int(config.get('config','vt_malware_threshold'))

	#Setup output options
	#Local
	local = config.get('config','local')
	if local == 'yes':
		history = open('history.csv', 'a')
		size = os.path.getsize('history.csv')
		#If new file, output header
		if size == 0: 
			output = "timestamp,environment,computer,file,path,size,md5,sha256,Source,wf_malware,wf_new,wf_upload,vt_positive,vt_total,vt_link,vt_new,vt_upload\n"
			history.write(output)
		if debug: print ("  Will output to local file")
		
	#Splunk
	splunk = config.get('config','splunk')
	if splunk == 'yes':		
		http_event_collector_key = config.get('config','splunk_key')
		http_event_collector_host = config.get('config','splunk_host')
		event = http_event_collector(http_event_collector_key, http_event_collector_host)
		payload = {}
		payload.update({"index":config.get('config','splunk_index')})
		payload.update({"sourcetype":config.get('config','splunk_sourcetype')})
		payload.update({"source":config.get('config','splunk_source')})
		if debug: print ("  Will output to Splunk")
	
	#Slack
	slack = config.get('config','slack')
	if slack == 'yes': 
		token = config.get('config','slack_token')
		username = config.get('config','slack_username')
		channel = config.get('config','slack_channel')
		if debug: print ("  Will output to Slack")
	
	#Email
	email = config.get('config','email')
	email_attachments = []
	if debug and email == 'yes': print ("  Will output to Email")
	
	now = datetime.datetime.now()
	timestamp = str(now.year) + '-' + '{:02d}'.format(now.month) + '-' + '{:02d}'.format(now.day) + ' ' + str(now.hour) + ':' + str(now.minute)
	
	#Output results to selected options
	for hash in hashes_list:
		computer    = hash[0]
		file        = hash[1]
		path        = hash[2]
		size        = hash[3]
		md5         = hash[4]
		sha256      = hash[5]
		source      = hash[6]
		wf_malware  = str(hash[7])
		wf_new      = str(hash[8])
		wf_upload   = str(hash[9])
		vt_positive = str(hash[10])
		vt_total    = str(hash[11])
		vt_link     = hash[12]
		vt_new      = str(hash[13])
		vt_upload   = str(hash[14])
		
		#Count malware hashes
		if wf_malware == 'yes' or int(vt_positive) >= vt_malware_threshold:
			stats['malware'] += 1
		
		#Output to CSV
		if local == 'yes':
			output = timestamp + ',' + environment + ',' + computer + ',' + file + ',' + path + ',' + size + ',' + md5 + ',' + sha256 + ',' + source + ',' + wf_malware + ',' + wf_new + ',' + wf_upload + ',' + vt_positive + ',' + vt_total + ',' + vt_link + ',' + vt_new + ',' + vt_upload + '\n'
			history.write(output)
		
		#Output to Splunk
		if splunk == 'yes':
			event_data = {'timestamp':timestamp, 'environment':environment, 'type':'detail', 'hash_source':'index', 'computer':computer, 'file':file, 'path':path, 'size':size, 'md5':md5, 'sha256':sha256, 'source':source, 'wf_malware':wf_malware, 'wf_new':wf_new, 'wf_upload':wf_upload, 'vt_positive':vt_positive, 'vt_total':vt_total, 'vt_link':vt_link, 'vt_new':vt_new, 'vt_upload':vt_upload}
			payload.update({'event':event_data})
			event.batchEvent(payload)
		
		#Output to Slack only if malware
		if slack == 'yes' and (wf_malware == 'yes' or int(vt_positive) >= vt_malware_threshold):
			text = ("MALWARE FOUND" + \
				"\nTimestamp: "        + timestamp + \
				"\nComputer: "         + computer + \
				"\nFile: "             + file + \
				"\nPath: "             + path + \
				"\nMD5: "              + md5 + \
				"\nSHA256: "           + sha256 + \
				"\nWildFire Malware: " + wf_malware + \
				"\nVirusTotal: "       + str(vt_positive) + '/' + str(vt_total) + \
				"\nVirusTotal Link: "  + vt_link)
			message = urllib2.quote(text)
			#results = 'emptyStatus'
			try:
				url = "https://slack.com/api/chat.postMessage?token=" + token + "&channel=" + channel + "&text=" + message + "&username=" + username + "&pretty=1"
				req = urllib2.Request(url)
				response = urllib2.urlopen(req)
				results = response.read()
			except (urllib2.HTTPError) as e:
				results = e;
				
		if wf_malware == 'yes' or int(vt_positive) >= vt_malware_threshold:
			details += "\nComputer: "         + computer
			details += "\nFile: "             + file
			details += "\nPath: "             + path
			details += "\nMD5: "              + md5
			details += "\nSHA256: "           + sha256
			details += "\nWildFire malware: " + wf_malware
			details += "\nVirusTotal: "       + str(vt_positive) + '/' + str(vt_total)
			details += "\nVirusTotal link: "  + vt_link + '\n'			
			email_attachments.append("reports\\" + md5 + ".pdf")

	#Output Final statistics and details
	computers_total  = str(stats['computers_total'])
	computers_hashes = str(stats['computers_hashes'])
	total            = str(stats['total'])
	excluded         = str(stats['excluded'])
	unique           = str(stats['unique'])
	wf_cache         = str(stats['wf_cache'])
	wf_new           = str(stats['wf_new'])
	wf_uploaded      = str(stats['wf_uploaded'])
	vt_cache         = str(stats['vt_cache'])
	vt_new           = str(stats['vt_new'])
	vt_uploaded      = str(stats['vt_uploaded'])
	malware          = str(stats['malware'])

	email_content = "\nTanFire Statistics" + \
		"\nComputers (total/with hashes): " + computers_total + '/' + computers_hashes + \
		"\nNew Tanium Index hashes: "       + total + \
		"\nExcluded: "                      + excluded + \
		"\nUnique: "                        + unique + \
		"\nWildFire cache: "                + wf_cache + \
		"\nWildFire direct: "               + wf_new + \
		"\nWildFire uploaded: "             + wf_uploaded + \
		"\nVirusTotal cache: "              + vt_cache + \
		"\nVirusTotal direct: "             + vt_new + \
		"\nMalware: "                       + malware + \
		"\n\nDetails on malware hashes: "   + details
		
	if debug:
		print(email_content)

	if local == 'yes':
		stats_file = open('stats.csv', 'a')
		size = os.path.getsize('stats.csv')
		#If new file, output header
		if size == 0: 
			output = "timestamp,type,computers_total,computers_hashes,total,excluded,unique,wf_cache,wf_new,wf_ploaded,vt_cache,vt_new,vt_uploaded,malware\n"
			stats_file.write(output)
		output = timestamp + ',index,' + computers_total + ',' + computers_hashes + ',' + total + ',' + excluded + ',' + unique + ',' + wf_cache + ',' + wf_new + ',' + wf_uploaded + ',' + vt_cache + ',' + vt_new + ',' + vt_uploaded + ',' + malware + '\n'
		stats_file.write(output)
		stats_file.close()
		
	if splunk == 'yes':	
			event_data = {'timestamp':timestamp, 'type':'summary', 'environment':environment, 'hash_source':'index', 'computers_total':computers_total, 'computers_hashes':computers_hashes, 'total':total, 'excluded':excluded, 'unique':unique, 'wf_cache':wf_cache, 'wf_new':wf_new, 'wf_uploaded':wf_uploaded, 'vt_cache':vt_cache, 'vt_new':vt_new, 'vt_uploaded':vt_uploaded, 'malware':malware}
			payload.update({'event':event_data})
			event.batchEvent(payload)	
	
	#Output to Email
	if email == 'yes': Email(timestamp, email_content, email_attachments)
	
	#Output cleanup
	if local == 'yes': history.close()
	if splunk == 'yes': event.flushBatch()


#Send statistics and details email
def Email(timestamp, email_content, files=None):	
	if debug: print ("\nFUNCTION output.Email")
	print files
	
	send_from = config.get('config','email_from')
	send_to = config.get('config','email_to')
	smtp_server = config.get('config','email_server')
	subject = "TanFire Malware Report - " + environment + " " + timestamp

	msg = MIMEMultipart()
	msg['From'] = send_from
	msg['To'] = send_to
	msg['Date'] = formatdate(localtime=True)
	msg['Subject'] = subject
	msg.attach(MIMEText(email_content))

	#Remove duplicate attachments
	attachments = []
	for i in files:
		if i not in attachments:
			attachments.append(i)
			
	for f in attachments or []:
		try:
			with open(f, "rb") as fil:
				part = MIMEApplication(fil.read(), Name=basename(f))
				part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
				msg.attach(part)
		except:
			if debug: print ("\nDownload of report failed: " + f)

	try:
		smtp = smtplib.SMTP(smtp_server)
		smtp.sendmail(send_from, send_to, msg.as_string())
		smtp.close()
	#Sometimes the connection fails the first time. Attempt a second connection if the first one fails.
	except:
		if debug: print ("\n IN EMAIL EXCEPT")
		smtp = smtplib.SMTP(smtp_server)
		time.sleep(2)
		smtp = smtplib.SMTP(smtp_server)
		smtp.sendmail(send_from, send_to, msg.as_string())		
		smtp.close()