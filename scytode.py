# Programmer: Brent 'becrevex' Chambers
# Date: July 20, 2020
# Filename: scytode.py
# Description:  Scytode Web Platform Identification Scanner

import re
import os
import csv
import requests
import argparse
import random
import time
import ipaddress
import traceback
import datetime
from queue import Queue
import threading
requests.packages.urllib3.disable_warnings() # disable lame SSL warnings (pfft)

help_example = """
   +---------------------------------------(support free info)---
   :". /  /  /
   :.-". /  /    Scytode Web Platform 
   : _.-". /              Identification Scanner
   :"  _.-".
   :-""     ".   EXAMPLE: scytode.py -r 104.28.18.0/24
   :
   : 
   :
 ^.-.^
'^\+/^`
'/`"'\`

"""
parser = argparse.ArgumentParser(description='Scytode Web Platform Identifier'+'\n\n'+ help_example, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-t', '--target')
parser.add_argument('-r', '--range')
parser.add_argument('-iL', '--inputfile', help='Specify a filename for bulk target scanning.')
#parser.add_argument('-oW', '--outputweb', help='Creates output file of discovered web servers.')
#parser.add_argument('-search', action='store_true', help='Searches IPv4 space for vulnerable hosts. (2 Second delay)')
args = parser.parse_args()

findings = {}
q = Queue()


def read_from_file(filepath):
	with open(filepath) as fd:
		targets = fd.read().splitlines()
	return targets

def execution_header():
	print("Scytode Web Identifier ( github.com/becrevex/Telerik_CVE-2019-18935 ) ")
	print(help_example)
	stamp = datetime.datetime.now()
	print("\nStarting platform identification scan at " + str(stamp))
	print()


def is_valid_ip(ip):
	"""Checks if IP is valid"""
	test = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip)
	if test:
		return True
	else:
		return False

def write_web_to_file(filename):
	""" Writes all collected IP:ServerTypes in findings to a csv"""
	w = csv.writer(open(filename, "w", newline=''))
	for key, val in findings.items():
		w.writerow([key, val])
	print("\nWeb discovery file saved as: ", filename)
	
def write_types_to_file():
	type_list = []
	for value in findings.values():
		type_list.append(value.split("/")[0])
	list_set = set(type_list)
	unique_list = (list(list_set))
	
	# create targets directory
	if not os.path.exists("./targets/"):
		os.makedirs("./targets/")
	
	# write each value to its respective type
	for server_type in unique_list:
		with open("./targets/"+server_type+".txt", 'a') as fd:
			for key, val in findings.items():
				if server_type in val:
					fd.write(key[8:]+"\n")

		# save each unique value and replace the "/"
	# for each value
		# open a file writing handle
	print(len(unique_list), "server types file saved.")

def is_valid_hostname(hostname):
    """Checks if hostname is valid for scanning """
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False
    labels = hostname.split(".")
    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False
    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)

def range_scan(netrange):
	""" Old iterative function, created for testing """
	for i in [str(ip) for ip in ipaddress.IPv4Network(netrange)]:
		check_https_bulk(i)
	
	
def threader():
	""" Threader function that calls the evaluation function """
	while True:
		worker = q.get()
		check_https_bulk(worker)
		q.task_done()
	print("Done.")
	stamp = datetime.datetime.now()
	print("\nPlatform identification scan completed at " + str(stamp))


def threaded_range_scanner(netrange):
	""" Range scanner that initiates the threaded scan """
	for x in range(10):
		t = threading.Thread(target = threader)
		t.daemon = True
		t.start()
		
	for worker in [str(ip) for ip in ipaddress.IPv4Network(netrange)]:
		q.put(worker)
		
	q.join()
	
def check_http_bulk(target):
	try:
		r = requests.get('http://'+ target, timeout=0.8, verify=False)
		status = r.status_code
		servertype = r.headers['Server']
		if status == 200:
			print(target, "   [+] Server: ", r.headers['Server'])
			findings["http://"+target] = r.headers['Server']
		else:
			pass
	except Exception as ex:
		pass



def check_https_bulk(target):
	""" Tests if a web server is listening, and pulls the server response type """
	try:
		r = requests.get('https://'+ target, timeout=0.5, verify=False)
		status = r.status_code
		servertype = r.headers['Server']
		if status == 200:
			print(target + "   [+] Server: ", r.headers['Server'])
			findings["https://"+target] = r.headers['Server']
		else:
			pass
	except Exception as ex:
		pass
	

if __name__=='__main__':
	if args.inputfile:
		execution_header()
		targets = read_from_file(args.inputfile)
		for host in targets:
			threaded_range_scanner(host)
		stamp = datetime.datetime.now()
		print("\nPlatform identification scan completed at " + str(stamp))
		write_web_to_file("output.csv")

	elif args.target:
		execution_header()
		if is_valid_ip(args.target):
			check_vuln(args.target)

		elif is_valid_hostname(args.target):
			check_vuln(args.target)
		stamp = datetime.datetime.now()
		print("Platform identification scan completed at " + str(stamp))

	#elif args.range:
	#	execution_header()
	#	range_scan(args.range)
	#	stamp = datetime.datetime.now()
	#	print("Platform identification scan completed at " + str(stamp))
		
	elif args.range:
		execution_header()
		threaded_range_scanner(args.range)
		stamp = datetime.datetime.now()
		print("\n[+] Platform identification scan completed at " + str(stamp))
		print("[+] Discovered web servers: ", len(findings.keys()))
		write_web_to_file("output.csv")
		write_types_to_file()
		
	else:
		parser.print_help()
else:
	parser.print_help()	