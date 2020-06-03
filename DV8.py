#!/usr/bin/python3

# DB8dotpy helps you identify deviations in HTTP responses.
# Specify a request file, payload file(s), attack mode 
# and deviator to use and DV8dotpy will flag any deviations in responses.
# Current deviators available: Cookie, Status Code, Content Length.

# Date: 31/05/2020
__version__ = '1.0'

import requests,argparse,sys,os,json,re,urllib.parse,urllib3,copy,numpy,collections
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import time,sleep
from itertools import product

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

success = 0
deviators={}
verbose=0
threads=5
redir=False
timeout=10
cert_check=True
proxy=""
proxies={}
analyse=""
code=0
clength_array=[]
parameter=""
inject_point=""
sensitivity=25
sstring="*P1*"
pattern = re.compile('§(.+?)§')
req_dict={}
revolver_counter=0
multi_payload=False
ppositions=0
out_path=""
http_ver=""
extensions=[]

def main():
    file_path = ""
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('-f', help='Supply the path to the HTTP request.',required=True, metavar='<Path to Request file>', type=str)
    parser.add_argument('-p', help='Supply the path to a list of payloads (One per-line). Multiple files can be provided for the following modes: trident(5), nuke',required=True, metavar='<Path to Payload file>', type=str, nargs='*')
    parser.add_argument('-v', help='Be verbose, i.e. Display response length and response code for each request.', action='store_true')
    parser.add_argument('-t', help='Set number of threads, 1-50. (Default=5)', metavar='<Threads>', type=int, choices=range(1, 51))
    parser.add_argument('-r', help='Follow redirects. (Default=False)', action='store_true')
    parser.add_argument('-q', help='Set request timeout in seconds, 1-60. (Default=10)', metavar='<Timeout>', type=int, choices=range(1, 60))
    parser.add_argument('-k', help='Insecure mode i.e. check certificate validity. (Default=True)', action='store_true')
    parser.add_argument('-x', help='Proxy (scheme://ipaddress:port)', metavar='<Proxy>', type=str)
    parser.add_argument('-d', help='Response attribute to analyse for deviation.(Options: code,cookie,clength,all)', required=True, metavar='<Deviator>', type=str, choices=["code","cookie","clength","all"])
    parser.add_argument('-c', help='Set expected status code. Any responses with different codes will be treated as deviations.', metavar='<HTTP Status Code>', type=int, choices=(200,403,302,300,400,401,403,404))
    parser.add_argument('-m', help='Attack Mode i.e. how and where to inject payloads. (Options: revolver,shotgun,trident,nuke)', required=True, metavar='<Attack Mode>', type=str, choices=["revolver","shotgun","trident","nuke"])
    parser.add_argument('-S', help='Set Content Length analysis sensitivity, from 1-30 (Lower number = more sensitive, [more false positives]. Vice versa.). (Default=25)', metavar='<Sensitivity>', type=int, choices=range(1, 31))
    parser.add_argument('-o', help='Supply the path to store the requests that produced deviated responses. Format: payload.deviator or position_payload.deviator if multiple payload positions specified.', metavar='<Path to Dir>', type=str)
    parser.add_argument('-a', help='Supply any string(s) you wish to append to the payload i.e. ".txt", ".php", "/".  You can supply more than one.', metavar='<String to append>', type=str, nargs='*')
    args = parser.parse_args()
    if args.m  != "revolver" and args.m != "shotgun" and args.m != "trident" and args.m != "nuke":
    	print('Sorry, {} mode not recognized, please check...'.format(args.m))
    	sys.exit()
    if (args.d=="code" or args.d=="all") and not args.c:
    	parser.error("-d [code|all] requires -c <HTTP Status Code> e.g. -d code -c 200")
    if args.c and not (args.d!="code" or args.d!="all"):
    	parser.error("-c <HTTP status code> can only be specified when using -d [code|all]. e.g. -d code -c 200")
    if args.o:
    	global out_path
    	if os.path.isdir(args.o):
    		out_path = args.o
    	else:
    		print("Invalid out path specified '{}'  Please check...".format(args.o))
    		sys.exit()
    file_path = args.f
    if args.m == "revolver" or args.m == "shotgun":
    	if len(args.p) > 1:
    		print("\r\n###Too many payload files specified.  Continuing with first payload file!###")
    	payload_path = args.p[0]
    else:
    	payload_path = args.p
    mode = args.m
    global analyse
    analyse = args.d
    if args.v:
    	global verbose
    	verbose=1
    if args.t:
    	global threads
    	threads = int(args.t)
    if args.S:
    	global sensitivity
    	sensitivity = int(args.S)
    if args.r:
    	global redir
    	redir=True
    if args.q:
    	global timeout
    	timeout = int(args.q)
    if args.k:
    	global cert_check
    	cert_check=False
    if args.x:
    	pattern = re.compile('(https?://.*):(\d*)')
    	if pattern.match(args.x):
    		global proxy
    		proxy = str(args.x)
    	else:
    		print("Invalid poxy format.  Please check.")
    		sys.exit()
    if args.c:
    	global code
    	code=args.c
    	analyse = args.d
    if args.a:
    	global extensions
    	extensions.append(args.a)
    return file_path,payload_path,mode

def file_exist(file_path):
	if os.path.exists(file_path):
		return True
	else:
		print("Error loading file: "+ str(file_path) +"  Please check file path.")
		sys.exit()

def read_file(file_path):
	fqdn = ""
	url_path = ""
	headers = {}
	with open(file_path, "r+") as file_object:
		lines = file_object.readlines()
		req_type = lines[0].split(' ')[0]
		if req_type != "POST" and req_type != "GET":
			print('Sorry, either {} is not a supported request type (yet) or the request file is malformed.'.format(req_type))
			sys.exit()
		url_path_raw = re.search(r'\s+(.+?)\s',lines[0])
		url_path = url_path_raw.group(1)
		global http_ver
		re_http_ver = re.search(r'HTTP\/\d\.\d',lines[0])
		http_ver = re_http_ver.group(0)
		fqdn_raw = re.search(r'\s+(.+?)\s',lines[1])
		fqdn = fqdn_raw.group(1)
		post_data = urllib.parse.parse_qs(lines[-1])
		for line in lines[2:-2]:
			h,sep,v = str(line).partition(':')
			headers[h]=v.strip()
		proto = test_https(fqdn,url_path)
	url = proto+fqdn+url_path
	return url,headers,post_data,req_type

def check_request_qstring(qstring):
	counter=0
	url = urllib.parse.urlparse(qstring)
	url_dirs = str(url.path).split("/")
	for url_dir in url_dirs:
		if pattern.match(url_dir):
			counter+=1
	parsed_qs = urllib.parse.parse_qs(urllib.parse.urlparse(qstring).query)
	for value in parsed_qs.values():
		if pattern.match(value[0]):
			counter+=1
	return counter

def check_request_headers(headers):
	counter=0
	for value in headers.values():
		if pattern.match(value):
			counter+=1
	return counter

def check_request_body(post_data):
	counter=0
	for value in post_data.values():
		if pattern.match(value[0]):
			counter+=1
	return counter

def append_request_items_revolver(payload,payload_dict,url,headers,postdata):
	if url:
		payload_dict[payload].update({"url":url})
	if headers:
		payload_dict[payload].update({"headers":headers})
	if postdata:
		payload_dict[payload].update({"postdata":postdata})
	return

def append_request_items(payload,url,headers,postdata):
	if url:
		if payload not in req_dict:
			req_dict[payload]=[{"url":url}]
		else:
			req_dict[payload].append({"url":url})
	if headers:
		if payload not in req_dict:
			req_dict[payload]=[{"headers":headers}]
		else:
			req_dict[payload].append({"headers":headers})
	if postdata:
		if payload not in req_dict:
			req_dict[payload]=[{"postdata":postdata}]
		else:
			req_dict[payload].append({"postdata":postdata})
	return

def inject_payload_qstring(og_qstring,payload):
	qstring = copy.deepcopy(og_qstring)
	url_parts = list(urllib.parse.urlparse(qstring))
	if "§" in url_parts[2]:
		path = re.split('/',url_parts[2])
		for n, i in enumerate(path):
			if pattern.search(i):
				path[n] = payload
				url_parts[2] = "/".join(path)
				url=urllib.parse.urlunparse(url_parts)
	query = dict(urllib.parse.parse_qsl(url_parts[4]))
	for key,value in query.items():
		if pattern.match(value):
			params = {key:payload}
			query.update(params)
			url_parts[4] = urllib.parse.urlencode(query)
			url=urllib.parse.urlunparse(url_parts)
	global req_dict
	if payload not in req_dict:
		req_dict[payload]=[{"url":url}]
	else:
		req_dict[payload].append({"url":url})

def inject_payload_headers(og_headers,payload):
	headers = copy.deepcopy(og_headers)
	for key,value in headers.items():
		if pattern.match(value):
			params = {key:payload}
			headers.update(params)
	global req_dict
	if payload not in req_dict:
		req_dict[payload]=[{"headers":headers}]
	else:
		req_dict[payload].append({"headers":headers})

def inject_payload_body(og_post_data,payload):
	post_data = copy.deepcopy(og_post_data)
	for key,value in post_data.items():
		if pattern.match(value[0]):
			params = {key:payload}
			post_data.update(params)
	global req_dict
	if payload not in req_dict:
		req_dict[payload]=[{"postdata":post_data}]
	else:
		req_dict[payload].append({"postdata":post_data})

def inject_payload_qstring_revolver(og_qstring,headers,postdata,payload,position,counter):
	payload_dict={}
	qstring = copy.deepcopy(og_qstring)
	url_parts = list(urllib.parse.urlparse(qstring))
	if "§" in url_parts[2]:
		path = re.split('/',url_parts[2])
		for n, i in enumerate(path):
			if pattern.search(i):
				if int(counter) == int(position):
					path[n] = payload
					url_parts[2] = "/".join(path)
					url=urllib.parse.urlunparse(url_parts)
				counter+=1
	if url_parts[4]!=0:
		query = dict(urllib.parse.parse_qsl(url_parts[4]))
		for key,value in query.items():
			if pattern.match(value):
				if int(counter) == int(position):
					params = {key:payload}
					query.update(params)
					url_parts[4] = urllib.parse.urlencode(query)
					url=urllib.parse.urlunparse(url_parts)
				counter+=1
	#§
	global req_dict
	payload_dict[payload]={"url":url}
	append_request_items_revolver(payload,payload_dict,None,headers,postdata)
	if position not in req_dict:
		req_dict[position]=[[payload_dict]]
	else:
		req_dict[position].append([payload_dict])

def inject_payload_headers_revolver(url,og_headers,postdata,payload,position,counter):
	payload_dict={}
	headers = copy.deepcopy(og_headers)
	for key,value in headers.items():
		if pattern.match(value):
			if int(counter) == int(position):
				params = {key:payload}
				headers.update(params)
			counter+=1
	global req_dict
	payload_dict[payload]={"headers":headers}
	append_request_items_revolver(payload,payload_dict,url,None,postdata)
	if position not in req_dict:
		req_dict[position]=[[payload_dict]]
	else:
		req_dict[position].append([payload_dict])

def inject_payload_body_revolver(url,headers,og_post_data,payload,position,counter):
	payload_dict={}
	post_data = copy.deepcopy(og_post_data)
	for key,value in post_data.items():
		if pattern.match(value[0]):
			if int(counter) == int(position):
				params = {key:payload}
				post_data.update(params)
			counter+=1
	global req_dict
	payload_dict[payload]={"postdata":post_data}
	append_request_items_revolver(payload,payload_dict,url,headers,None)
	if position not in req_dict:
		req_dict[position]=[[payload_dict]]
	else:
		req_dict[position].append([payload_dict])

def inject_payload_qstring_trident_nuke_single(og_qstring,payloads,p_key,position):
	qstring = copy.deepcopy(og_qstring)
	url_parts = list(urllib.parse.urlparse(qstring))

	if "§" in url_parts[2]:
		path = re.split('/',url_parts[2])
		for n, i in enumerate(path):
			if pattern.search(i):
				if int(counter) == int(position):
					path[n] = payload
					url_parts[2] = "/".join(path)
					url=urllib.parse.urlunparse(url_parts)

	query = dict(urllib.parse.parse_qsl(url_parts[4]))
	for key,value in query.items():
		if pattern.match(value):
			payload=payloads[position-1]
			params = {key:payload}
			query.update(params)
			url_parts[4] = urllib.parse.urlencode(query)
			url=urllib.parse.urlunparse(url_parts)
	global req_dict
	if p_key not in req_dict:
		req_dict[p_key]=[{"url":url}]
	else:
		req_dict[p_key].append({"url":url})

def inject_payload_headers_trident_nuke_single(og_headers,payloads,p_key,position):
	headers = copy.deepcopy(og_headers)
	for key,value in headers.items():
		if pattern.match(value):
			payload=payloads[position-1]
			params = {key:payload}
			headers.update(params)
	global req_dict
	if p_key not in req_dict:
		req_dict[p_key]=[{"headers":headers}]
	else:
		req_dict[p_key].append({"headers":headers})

def inject_payload_body_trident_nuke_single(og_post_data,payloads,p_key,position):
	post_data = copy.deepcopy(og_post_data)
	for key,value in post_data.items():
		if pattern.match(value[0]):
			payload=payloads[position-1]
			params = {key:payload}
			post_data.update(params)
	global req_dict
	if p_key not in req_dict:
		req_dict[p_key]=[{"postdata":post_data}]
	else:
		req_dict[p_key].append({"postdata":post_data})

def inject_payload_qstring_trident_nuke(og_qstring,headers,postdata,p_key,payloads,position,counter):
	payload_dict={}
	qstring = copy.deepcopy(og_qstring)
	url_parts = list(urllib.parse.urlparse(qstring))

	if "§" in url_parts[2]:
		path = re.split('/',url_parts[2])
		for n, i in enumerate(path):
			if pattern.search(i):
				if int(counter) == int(position):
					path[n] = payloads[position-1]
					url_parts[2] = "/".join(path)
					url=urllib.parse.urlunparse(url_parts)
					position+=1
				counter+=1

	query = dict(urllib.parse.parse_qsl(url_parts[4]))
	for key,value in query.items():
		if pattern.match(value):
			if int(counter) == int(position):
				payload=payloads[position-1]
				params = {key:payload}
				query.update(params)
				url_parts[4] = urllib.parse.urlencode(query)
				url=urllib.parse.urlunparse(url_parts)
				#print("URL Assigned {} at {} with - Counter: {}, Position: {}".format(payload,value,counter,position))
				position+=1
			counter+=1	
	#§	
	global req_dict
	if p_key not in req_dict:
		req_dict[p_key]=[{"url":url}]
	else:
		req_dict[p_key].append({"url":url})
	return position

def inject_payload_headers_trident_nuke(url,og_headers,postdata,p_key,payloads,position,counter):
	payload_dict={}
	headers = copy.deepcopy(og_headers)
	for key,value in headers.items():
		if pattern.match(value):
			if int(counter) == int(position):
				payload=payloads[position-1]
				params = {key:payload}
				headers.update(params)
				#print("Headers Assigned {} at {} with - Counter: {}, Position: {}".format(payload,value,counter,position))
				position+=1
			counter+=1
	global req_dict
	if p_key not in req_dict:
		req_dict[p_key]=[{"headers":headers}]
	else:
		req_dict[p_key].append({"headers":headers})
	return position

def inject_payload_body_trident_nuke(url,headers,og_post_data,p_key,payloads,position,counter):
	payload_dict={}
	post_data = copy.deepcopy(og_post_data)
	for key,value in post_data.items():
		if pattern.match(value[0]):
			if int(counter) == int(position):
				payload=payloads[position-1]
				params = {key:payload}
				post_data.update(params)
				#print("Body Assigned {} at {} with - Counter: {}, Position: {}".format(payload,value,counter,position))
				position+=1
			counter+=1
	if p_key not in req_dict:
		req_dict[p_key]=[{"postdata":post_data}]
	else:
		req_dict[p_key].append({"postdata":post_data})

def print_settings(mode):
	if analyse=="cookie":
		analyse_cname="Cookie"
	elif analyse=="code":
		analyse_cname="Status Code"
	elif analyse=="clength":
		analyse_cname="Content Length"
	else:
		analyse_cname="Cookie, Status Code and Content Length"
	print("\r\n===============================================================================")
	print("Attack Mode: ",mode)
	if multi_payload:
		print("Payload Positions: ",ppositions)
	print("Threads: "+str(threads))
	print("Timeout: "+str(timeout))
	print("Follow Redirects: "+str(redir))
	print("Check Certificate: "+str(cert_check))
	if proxy:
		print("Proxy: "+str(proxy))
	print("Analyse: ",analyse_cname)
	print("CLength Sensitivity: ",sensitivity)
	print("===============================================================================")

def test_https(fqdn,raw_url_path):
	url_path = strip_positional_indicators(raw_url_path)
	url_s = "https://"+fqdn
	url = "http://"+fqdn
	try:
		r = requests.get(url_s, timeout=5)
		if r.status_code:
			protocol = "https://"
			if proxy:
				proxies["https"]=proxy
			return protocol
	except:
		pass
	try:
		r = requests.get(url, timeout=5)
		if r.status_code:
			protocol = "http://"
			if proxy:
				proxies["http"]=proxy
			return protocol
	except requests.exceptions.RequestException:
		print("Can't conact site.  Check network connection or retry later.")
		raise SystemExit(0)

def send_request(url,headers,postdata,req_type):
	try:
		if req_type == "POST":
			response = requests.post(url, data=postdata, headers=headers, verify=cert_check, allow_redirects=redir, timeout=timeout, proxies=proxies)
			return(response)
		elif req_type == "GET":
			response = requests.get(url, headers=headers, verify=cert_check, allow_redirects=redir, timeout=timeout, proxies=proxies)
			return(response)
	except requests.exceptions.Timeout as e:
		for attempt in range(3):
			try:
				sleep(5)
				if req_type == "POST":
					response = requests.post(url, data=postdata, headers=headers, verify=cert_check, allow_redirects=redir, timeout=timeout, proxies=proxies)
					return(response)
				elif req_type == "GET":
					response = requests.get(url, headers=headers, verify=cert_check, allow_redirects=redir, timeout=timeout, proxies=proxies)
					return(response)
			except:
				print("Connection Error.  Retrying...")
				print(e)
	except requests.exceptions.RequestException:
		if proxy:
			print("\r\nConnection Error.  Check Proxy!")
			sys.exit()
		print("Fatal Error - Exiting...")
		raise SystemExit(0)

def handle_response(response,payload1):
	if multi_payload:
		payload = payload1[1:]
		position = payload1[0]
	codes=[100,101,102,200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,307,308,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,421,422,423,424,426,428,429,431,444,451,499,500,501,502,503,504,505,506,507,508,510,511,599]
	if response.status_code in codes:
		clength = int(len(str(response.text))+len(str(response.headers)))
		if redir:
			if response.history:
				response=response.history[0]
		if verbose==1:
			if multi_payload:
				print("\r\n\r\nResults for Position: {} Payload: {}".format(position,payload))
			else:
				print("\r\n\r\nResults for: ",payload1)
			print("Response Code: "+ str(response.status_code))
			print("Response Length: ", clength)
			if response.cookies:
				print("Cookies: "+str(response.cookies))
		if analyse=="cookie":
			if multi_payload:
				analyse_cookies(response,payload,position)
			else:
				analyse_cookies(response,payload1,None)

		elif analyse=="code":
			if multi_payload:
				analyse_code(response,payload,position)
			else:
				analyse_code(response,payload1,None)

		elif analyse=="clength":
			if multi_payload:
				analyse_clength(payload,clength,position)
			else:
				analyse_clength(payload1,clength,None)
		
		elif analyse=="all":
			if multi_payload:
				analyse_cookies(response,payload,position)
				analyse_code(response,payload,position)
				analyse_clength(payload,clength,position)
			else:
				analyse_cookies(response,payload1,None)
				analyse_code(response,payload1,None)
				analyse_clength(payload1,clength,None)
	else:
		if verbose==1:
			print("Unknown response status code received!")

def analyse_cookies(response,payload,position):
	if response.cookies:
		global success
		global deviators
		success +=1
		if not deviators.get("Cookie"):
			if multi_payload:
				deviators["Cookie"]=[position+payload]
				if out_path:
					write_request_to_file(response,payload,position)
			else:
				deviators["Cookie"]=[payload]
				if out_path:
					write_request_to_file(response,payload,None)
		else:
			if multi_payload:
				deviators["Cookie"].append(position+payload)
				if out_path:
					write_request_to_file(response,payload,position)
			else:
				deviators["Cookie"].append(payload)
				if out_path:
					write_request_to_file(response,payload,None)

def analyse_code(response,payload,position):
	global code
	global success
	if response.status_code != code:
		success+=1
		if not deviators.get("Status Code"):
			if multi_payload:
				deviators["Status Code"]=[position+payload]
				if out_path:
					write_request_to_file(response,payload,position)
			else:
				deviators["Status Code"]=[payload]
				if out_path:
					write_request_to_file(response,payload,None)
		else:
			if multi_payload:
				deviators["Status Code"].append(position+payload)
				if out_path:
					write_request_to_file(response,payload,position)
			else:
				deviators["Status Code"].append(payload)
				if out_path:
					write_request_to_file(response,payload,None)

def analyse_clength(payload,clength,position):
	global success
	global clength_array
	if not clength_array:
		clength_array.append(clength)
	else:
		if deviated_clength(clength):
			success+=1
			if not deviators.get("Content Length"):
				if multi_payload:
					deviators["Content Length"]=[position+payload]
					if out_path:
						write_request_to_file(response,payload,position)
				else:
					deviators["Content Length"]=[payload]
					if out_path:
						write_request_to_file(response,payload,None)
			else:
				if multi_payload:
					deviators["Content Length"].append(position+payload)
					if out_path:
						write_request_to_file(response,payload,position)
				else:
					deviators["Content Length"].append(payload)
					if out_path:
						write_request_to_file(response,payload,None)
		else:
			clength_array.append(clength)

def deviated_clength(clength):
	global clength_array
	new_clength_array = copy.copy(clength_array)
	new_clength_array.append(clength)
	og_mean = numpy.mean(clength_array)
	og_stdd = numpy.std(clength_array)
	new_mean = numpy.mean(new_clength_array)
	new_stdd = numpy.std(new_clength_array)
	if verbose==1:
		print("Original Mean: ",og_mean)
		print("Original Std Deviation: ",og_stdd)
		print("New Mean: ",new_mean)
		print("New Std Deviation: ",new_stdd)
	if new_stdd > sensitivity:
		return True
	else:
		return False

def write_request_to_file(response,payload,position):
	if position:
		file_path = out_path+"/"+position+"_"+payload+".deviator"
	else: 
		file_path = out_path+"/"+payload+".deviator"
	try:
		with open(file_path, "w") as file_object:
			file_object.write("{} {} {}\r\n".format(str(response.request.method), str(response.request.path_url),http_ver))
			fqdn_raw = re.search(r'//(.+?)/',response.request.url)
			host = fqdn_raw.group(1)
			file_object.write("Host: {}\r\n".format(host))
			for key, value in response.request.headers.items():
				file_object.write("{}: {}\r\n".format(key, value))
			file_object.write("\r\n{}".format(response.request.body))
	except:
		raise

def create_post_body_array(payload_path,post_data):
	post_array=[]
	with open(payload_path, "r+") as file_object:
		payloads = file_object.readlines()
		if ' ' in payloads[0]:
			print("Please ensure your payloads are one per line and don't contain spaces.\r\n")
			sys.exit()
		for payload in payloads:
			new_post_data = copy.deepcopy(post_data)
			new_post_data[parameter] = payload.strip()
			post_array.append(new_post_data)
	return post_array

def create_url_array(payload_path,url):
	url_array=[]
	with open(payload_path, "r+") as file_object:
		payloads = file_object.readlines()
		for payload in payloads:
			params={parameter:payload}
			x = copy.deepcopy(url)

			url_parts = list(urllib.parse.urlparse(x))
			query = dict(urllib.parse.parse_qsl(url_parts[4]))
			query.update(params)
			url_parts[4] = urllib.parse.urlencode(query)
			y=urllib.parse.urlunparse(url_parts)
			url_array.append(y)
	return url_array

def create_headers_array(payload_path,headers):
	headers_array=[]
	with open(payload_path, "r+") as file_object:
		payloads = file_object.readlines()
		for payload in payloads:
			new_headers_data = copy.deepcopy(headers)
			params={parameter:payload.strip()}
			new_headers_data.update(params)
			headers_array.append(new_headers_data)
	return headers_array

def get_array_length(array):
	array_len = len(array)
	return array_len

#Author of printProgressBar: Greenstick, https://stackoverflow.com/questions/3173320/text-progress-bar-in-the-console
def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print('\r%s |\033[38;5;208m%s\033[0m| %s%% %s' % (prefix, bar, percent, suffix), end = printEnd)
    # Print New Line on Complete
    if iteration == total: 
        print()

def handle_revolver(payloads,post_data,url,headers):
	global multi_payload
	global ppositions
	counter=1
	revolver_qstring = check_request_qstring(url)
	revolver_headers = check_request_headers(headers)
	revolver_body = check_request_body(post_data)
	sum_injection_points = (revolver_body+revolver_qstring+revolver_headers)
	if sum_injection_points == 0:
		print("Sorry, no payload positions found in request file.  Please check again...")
		sys.exit()
	if sum_injection_points > 9:
		print("Sorry, too many payload positions found in request file. Max is 9.  Please check again...")
		sys.exit()
	ppositions = sum_injection_points
	multi_payload=True
	if revolver_qstring > 0:
		for payload in payloads:
			for badposition in range(0,revolver_qstring):
				position = badposition+1
				inject_payload_qstring_revolver(url,headers,post_data,payload,position,counter)
		counter+=revolver_qstring
	if revolver_headers > 0:
		for payload in payloads:
			for badposition in range(revolver_qstring,(revolver_qstring+revolver_headers)):
				position = badposition+1
				inject_payload_headers_revolver(url,headers,post_data,payload,position,counter)
		counter+=revolver_headers
	if revolver_body > 0:
		for payload in payloads:
			for badposition in range((revolver_qstring+revolver_headers),(revolver_qstring+revolver_headers+revolver_body)):
				position = badposition+1
				inject_payload_body_revolver(url,headers,post_data,payload,position,counter)
	return sum_injection_points

def handle_trident(payloads_list,url,headers,post_data,num_pl_files):
	global ppositions
	global multi_payload
	length = len(payloads_list[0])
	if all(len(lst) != length for lst in payloads_list[1:]):
		print("Payload lists must be of equal length.  Please check and retry...")
		sys.exit()
	trident_qstring = check_request_qstring(url)
	trident_headers = check_request_headers(headers)
	trident_body = check_request_body(post_data)
	sum_injection_points = (trident_qstring+trident_headers+trident_body)
	if sum_injection_points != num_pl_files:
		print("The number of payload positions differs from the number of payload files specified.  Please check and retry...")
		sys.exit()
	if sum_injection_points == 0:
		print("Sorry, no payload positions found in request file.  Please check again...")
	ppositions = sum_injection_points
	for payload_tuples in zip(*payloads_list):
		payloads = list(payload_tuples)
		p_key = "§*§".join(payloads)
		position=1
		counter=1
		if trident_qstring > 1:
			inject_payload_qstring_trident_nuke(url,headers,post_data,p_key,payloads,position,counter)
		elif trident_qstring ==1:
			inject_payload_qstring_trident_nuke_single(url,payloads,p_key,position)
		else:	
			append_request_items(p_key,url,None,None)
		counter+=trident_qstring
		position+=trident_qstring
		if trident_headers > 1:	
			inject_payload_headers_trident_nuke(url,headers,post_data,p_key,payloads,position,counter)
		elif trident_headers ==1:
			inject_payload_headers_trident_nuke_single(headers,payloads,p_key,position)
		else:
			append_request_items(p_key,None,headers,None)
		counter+=trident_headers
		position+=trident_headers
		if trident_body > 1:
			inject_payload_body_trident_nuke(url,headers,post_data,p_key,payloads,position,counter)
		elif trident_body ==1:
			inject_payload_body_trident_nuke_single(post_data,payloads,p_key,position)
		else:	
			append_request_items(p_key,None,None,post_data)
	return sum_injection_points

def handle_nuke(payloads_list,url,headers,post_data,num_pl_files):
	global ppositions
	global multi_payload
	nuke_qstring = check_request_qstring(url)
	nuke_headers = check_request_headers(headers)
	nuke_body = check_request_body(post_data)
	sum_injection_points = (nuke_qstring+nuke_headers+nuke_body)
	if sum_injection_points != num_pl_files:
		print("The number of payload positions differs from the number of payload files specified.  Please check and retry...")
		sys.exit()
	if sum_injection_points == 0:
		print("Sorry, no payload positions found in request file.  Please check again...")
	ppositions = sum_injection_points
	for payload_tuples in product(*payloads_list):
		payloads = list(payload_tuples)
		p_key = "§*§".join(payloads)
		position=1
		counter=1
		if nuke_qstring > 1:
			inject_payload_qstring_trident_nuke(url,headers,post_data,p_key,payloads,position,counter)
		elif nuke_qstring ==1:
			inject_payload_qstring_trident_nuke_single(url,payloads,p_key,position)
		else:	
			append_request_items(p_key,url,None,None)
		counter+=nuke_qstring
		position+=nuke_qstring
		if nuke_headers > 1:	
			inject_payload_headers_trident_nuke(url,headers,post_data,p_key,payloads,position,counter)
		elif nuke_headers ==1:
			inject_payload_headers_trident_nuke_single(headers,payloads,p_key,position)
		else:
			append_request_items(p_key,None,headers,None)
		counter+=nuke_headers
		position+=nuke_headers
		if nuke_body > 1:
			inject_payload_body_trident_nuke(url,headers,post_data,p_key,payloads,position,counter)
		elif nuke_body ==1:
			inject_payload_body_trident_nuke_single(post_data,payloads,p_key,position)
		else:	
			append_request_items(p_key,None,None,post_data)
	return sum_injection_points

def handle_shotgun(payloads,url,headers,post_data):
	global ppositions
	shotgun_qstring = check_request_qstring(url)
	shotgun_headers = check_request_headers(headers)
	shotgun_body = check_request_body(post_data)
	sum_injection_points = (shotgun_qstring+shotgun_headers+shotgun_body)
	if sum_injection_points == 0:
		print("Sorry, no payload positions found in request file.  Please check again...")
		sys.exit()
	if sum_injection_points > 9:
		print("Sorry, too many payload positions found in request file. Max is 9.  Please check again...")
		sys.exit()
	ppositions = sum_injection_points
	for payload in payloads:
		if shotgun_qstring:
			inject_payload_qstring(url,payload)
		else:
			append_request_items(payload,url,None,None)
		if shotgun_headers:
			inject_payload_headers(headers,payload)
		else:
			append_request_items(payload,None,headers,None)
		if shotgun_body:
			inject_payload_body(post_data,payload)
		else:
			append_request_items(payload,None,None,post_data)

def get_payloads_from_file(payload_path):
	payload_dict=[]
	with open(payload_path, "r+") as file_object:
		payloads = file_object.readlines()
		for payload in payloads:
			if extensions:
				for extension in extensions[0]:
					payload_dict.append(payload.strip()+extension)
			payload_dict.append(payload.strip())
		return payload_dict	

def strip_positional_indicators(raw_url):
	if '§' in raw_url:
		url = raw_url.replace('§','')
		return url
	else:
		return raw_url

def strip_positional_indicators_headers(headers):
	for key,value in headers.items():
		if '§' in value:
			payload = value.replace('§','')
			params = {key:payload}
			headers.update(params)
	return headers

def strip_positional_indicators_post_data(post_data):
	for key,value in post_data.items():
		if '§' in value[0]:
			payload = value[0].replace('§','')
			params = {key:payload}
			post_data.update(params)
	return post_data

def print_results():
	if success > 0:
		print("===============================================================================")
		if success==1:
			print("Woohoo! 1 deviation found!")
		else:
			print("Woohoo! {} deviations found!".format(success))
		print(f'Time taken: {time() - start}')
		print("===============================================================================")
		part = "§*§"
		for key, values in deviators.items():
			print('########## {} Deviations ##########'.format(key))
			for deviator in values:
					if multi_payload:
						payload = deviator[1:]
						position = deviator[0]
						print("\033[38;5;208mPosition: {}, Payload: {}\033[0m".format(position,payload))
					elif part in deviator:
						deviator_list = deviator.split(part)
						i=1
						for single_deviator in deviator_list:
							print("\033[38;5;208mPosition: {}, Payload: {}\033[0m".format(i,single_deviator))
							i+=1
						print("###")	
					else:
						print(str("\033[38;5;208m{}\033[0m".format(deviator)))
		print("===============================================================================\r\n")
	else:
		print("\r\n===============================================================================")
		print("Sorry chap! No deviations found!")
		print(f'Time taken: {time() - start}')
		print("===============================================================================\r\n")

def welcome():
	with open('intro.txt', 'r') as f:
		greeting = f.read()
		print("\033[38;5;208m{}\033[0m".format(greeting))
		print("\r\nHelping you identify deviations in HTTP responses.")
		print("Author: Ben Millar (@grubbychicken)")

if __name__ == "__main__":
	welcome()
	start = time()
	file_path,payload_path,mode = main()
		
	if mode == "revolver":
		good_req_path = file_exist(file_path)
		good_pl_path = file_exist(payload_path)
		if good_req_path and good_pl_path:
			url,headers,post_data,req_type = read_file(file_path)
			payload_dict = get_payloads_from_file(payload_path)
			positions = handle_revolver(payload_dict,post_data,url,headers)
			print_settings(mode)
			array_len = get_array_length(payload_dict*positions)
			printProgressBar(0, array_len, prefix = 'Progress:', suffix = 'Complete |', length = 50)
			processes = {}
			i=0
			with ThreadPoolExecutor(max_workers=threads) as executor:
				for position in range(1,(positions+1)):
					pl_position =position
					for position in req_dict[position]:
						for request in position:
							for payload_key in request.keys():
								payload = str(pl_position)+payload_key
							for request_data in request.values():
								badurl = request_data['url']
								url=strip_positional_indicators(badurl)
								badheaders = request_data['headers']
								headers=strip_positional_indicators_headers(badheaders)
								if 'postdata' in request_data:
									badpost_data = request_data['postdata']
									post_data=strip_positional_indicators_post_data(badpost_data)
								processes.update({payload:executor.submit(send_request,url,headers,post_data,req_type)})
				for payload, task in processes.items():
					as_completed(task)
					response = task.result()
					handle_response(response,payload)
					i+=1
					printProgressBar(i, array_len, prefix = 'Progress:', suffix = 'Complete |', length = 50)
			print_results()
	
	elif mode == "shotgun":
		good_req_path = file_exist(file_path)
		good_pl_path = file_exist(payload_path)
		if good_req_path and good_pl_path:
			url,headers,post_data,req_type = read_file(file_path)
			payload_dict = get_payloads_from_file(payload_path)
			handle_shotgun(payload_dict,url,headers,post_data)
			print_settings(mode)
			array_len = get_array_length(payload_dict)
			printProgressBar(0, array_len, prefix = 'Progress:', suffix = 'Complete |', length = 50)
			processes = {}
			i=0
			with ThreadPoolExecutor(max_workers=threads) as executor:
				for payload,request_data in req_dict.items():
					url = request_data[0]['url']
					headers = request_data[1]['headers']
					if len(request_data) > 2:
						post_data = request_data[2]['postdata']
					processes.update({payload:executor.submit(send_request,url,headers,post_data,req_type)})
				for payload, task in processes.items():
					as_completed(task)
					response = task.result()
					handle_response(response,payload)
					i+=1
					printProgressBar(i, array_len, prefix = 'Progress:', suffix = 'Complete |', length = 50)
			print_results()

	elif mode == "trident":
		num_pl_files = len(payload_path)
		if num_pl_files <2:
			print("Please specify at least 2 payload files for {} mode".format(mode))
			sys.exit()
		elif num_pl_files >5:
			print("Sorry, I can only process up to 5 payload files :(")
			sys.exit()
		good_req_path = file_exist(file_path)
		for payload_file in payload_path:
			good_pl_path = file_exist(payload_file)
			if not good_pl_path:
				print("Sorry, can't find payload file '{}'.  Please check and try again...")
				sys.exit()
		if good_req_path:
			url,headers,post_data,req_type = read_file(file_path)
			payloads_list=[]
			for payload_file in payload_path:
				payloads = get_payloads_from_file(payload_file)
				payloads_list.append(payloads)
			handle_trident(payloads_list,url,headers,post_data,num_pl_files)
			print_settings(mode)
			array_len = get_array_length(payloads_list[0])
			printProgressBar(0, array_len, prefix = 'Progress:', suffix = 'Complete |', length = 50)
			processes = {}
			i=0
			with ThreadPoolExecutor(max_workers=threads) as executor:
				for payload,request_data in req_dict.items():
					url = request_data[0]['url']
					headers = request_data[1]['headers']
					if len(request_data) > 2:
						post_data = request_data[2]['postdata']
					processes.update({payload:executor.submit(send_request,url,headers,post_data,req_type)})
				for payload, task in processes.items():
					as_completed(task)
					response = task.result()
					handle_response(response,payload)
					i+=1
					printProgressBar(i, array_len, prefix = 'Progress:', suffix = 'Complete |', length = 50)
			print_results()

	elif mode == "nuke":
		num_pl_files = len(payload_path)
		if num_pl_files <2:
			print("Please specify at least 2 payload files for {} mode".format(mode))
			sys.exit()
		elif num_pl_files >5:
			print("Sorry, I can only process up to 5 payload files :(")
			sys.exit()
		good_req_path = file_exist(file_path)
		for payload_file in payload_path:
			good_pl_path = file_exist(payload_file)
			if not good_pl_path:
				print("Sorry, can't find payload file '{}'.  Please check and try again...")
				sys.exit()
		if good_req_path:
			url,headers,post_data,req_type = read_file(file_path)
			payloads_list=[]
			for payload_file in payload_path:
				payloads = get_payloads_from_file(payload_file)
				payloads_list.append(payloads)
			handle_nuke(payloads_list,url,headers,post_data,num_pl_files)
			print_settings(mode)
			array_len = get_array_length(req_dict)
			printProgressBar(0, array_len, prefix = 'Progress:', suffix = 'Complete |', length = 50)
			processes = {}
			i=0
			with ThreadPoolExecutor(max_workers=threads) as executor:
				for payload,request_data in req_dict.items():
					url = request_data[0]['url']
					headers = request_data[1]['headers']
					if len(request_data) > 2:
						post_data = request_data[2]['postdata']
					processes.update({payload:executor.submit(send_request,url,headers,post_data,req_type)})
				for payload, task in processes.items():
					as_completed(task)
					response = task.result()
					handle_response(response,payload)
					i+=1
					printProgressBar(i, array_len, prefix = 'Progress:', suffix = 'Complete |', length = 50)
			print_results()

# Known BUGS:
#
#
#
# TO DO:
# 
# Stop bening lazy - Implement classes! Get rid of global vars!
# 
# Add grep deviator - i.e. grep response for keyword/phrase?
#
# error checking!  Be better!
# 
# check inside referer header for payload position.  Just another urllib.parse....
# 
# 
#
# Could do with more testing.