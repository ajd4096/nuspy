#!/usr/bin/env python3.5

import argparse
import bs4
import calendar
import os
import requests
import sqlite3
import time
import warnings
#import binascii
#import calendar
#import csv
#import functools
#import hashlib
#import re
#import shutil
#import struct
#import sys
#import urllib.request

# My modules
import nuspy.global_vars	as global_vars

def	update_db_tagaya():

	#conn = sqlite3.connect(':memory:')
	conn = sqlite3.connect('nuspy-tagaya.db')

	csr = conn.cursor()

	# Create our tables
	csr.execute('''CREATE TABLE IF NOT EXISTS list_info (
			list_version	INTEGER,
			last_modified	INTEGER,
			PRIMARY KEY (list_version)
		)''')

	csr.execute('''CREATE TABLE IF NOT EXISTS title_info (
			title_id	TEXT,
			title_version	INTEGER,
			list_version	INTEGER,
			PRIMARY KEY(title_id, title_version)
		)''')

	conn.commit()

	# I have checked every versionlist for each region - they are always the same.
	#for r in ['JAP', 'USA', 'EUR']:
	for r in ['JAP']:
		fqdn='tagaya.wup.shop.nintendo.net'
		current_v = 1

		# Get the "latest_version" file direct from Nintendo
		if r == "JAP":
			url	= "https://tagaya.wup.shop.nintendo.net/tagaya/versionlist/JAP/JP/latest_version"
		elif r == "USA":
			url	= "https://tagaya.wup.shop.nintendo.net/tagaya/versionlist/USA/US/latest_version"
		elif r == "EUR":
			url	= "https://tagaya.wup.shop.nintendo.net/tagaya/versionlist/EUR/EU/latest_version"

		# Using Nintendo server certs from 0005001B-10054000, converted using
		'''
		# Bundle server cert files from updates/0005001B10054000/extracted/content/scerts/
		BUNDLE=nintendo_cert_bundle.pem
		rm -f $BUNDLE
		for X in CACERT_NINTENDO_*.der; do
			openssl x509 -inform DER -in $X -outform PEM >> $BUNDLE
		done

		# Check the bundle works
		if echo -n "" | openssl s_client -connect tagaya.wup.shop.nintendo.net:443 -CAfile $BUNDLE; then
			echo "Bundle OK"
		fi
		'''

		# If we have the ca cert file, use it
		# Otherwise ignore the SSL warning and fetch the url anyway
		ca_file='nintendo_cert_bundle.pem'
		if os.path.isfile(ca_file):
			verify = ca_file
		else:
			verify = False
		warnings.filterwarnings("ignore", message="Unverified HTTPS request is being made.*")
		warnings.filterwarnings("ignore", message="Certificate for tagaya-wup.cdn.nintendo.net has no `subjectAltName`.*")

		if global_vars.options.verbose:
			print("Fetching %s" % url)

		html = requests.get(url, verify=verify)
		if html:
			soup = bs4.BeautifulSoup(html.text, "html.parser")
			current_v	= int(soup.version.string)
			fqdn		= soup.fqdn.string

		# Get the highest version we have seen
		csr = conn.cursor()
		csr.execute('''SELECT IFNULL(MAX(list_version), 1) FROM list_info''')
		highest_v = int(csr.fetchone()[0])
		if global_vars.options.verbose:
			print("Current list version: %d" % current_v)
			print("Highest list version in DB: %d" % highest_v)

		for list_v in range(highest_v +1, current_v +1):
			# Get the "NNN.versionlist" file from the CDN
			if r == "JAP":
				url	= "https://%s/tagaya/versionlist/JAP/JP/list/%s.versionlist" % (fqdn, list_v)
			elif r == "USA":
				url	= "https://%s/tagaya/versionlist/USA/US/list/%s.versionlist" % (fqdn, list_v)
			elif r == "EUR":
				url	= "https://%s/tagaya/versionlist/EUR/EU/list/%s.versionlist" % (fqdn, list_v)

			#print(r, url)
			if global_vars.options.verbose:
				print("Fetching %s" % url)
			html = requests.get(url, verify=verify)
			if html:
				# Get the time from the URL's Last-Modified header if it exists
				last_modified = html.headers['Last-Modified']
				if last_modified:
					# Get the time as seconds-since-epoch UTC
					t = calendar.timegm(time.strptime(last_modified, '%a, %d %b %Y %H:%M:%S %Z'))
				else:
					t = 0
				#print(r, list_v, t)
				csr.execute("INSERT OR IGNORE INTO list_info VALUES (?, ?)", (list_v, t))

				soup = bs4.BeautifulSoup(html.text, "html.parser")
				#print(soup)
				titles = soup.find("titles")
				#print(titles)
				for title in titles.findAll("title"):
					#print(title)
					title_i	= title.find("id").string
					title_v	= title.find("version").string
					#print(r, title_i, title_v, list_v)
					csr.execute("INSERT OR IGNORE INTO title_info VALUES (?, ?, ?)", (title_i, title_v, list_v))
				conn.commit()
	# Close the DB connection
	conn.close()

def	main():
	parser = argparse.ArgumentParser(description='wiiubrew DB tool')
	parser.add_argument('-v',	'--verbose',	dest='verbose',		help='verbose output',				action='count',			default=0)
	parser.add_argument('-f',	'--fetch',	dest='fetch',		help='Fetch current tables from tagaya',	action='store_true',		default=False)

	global_vars.options = parser.parse_args()
	#print(type(vars(global_vars.options)), vars(global_vars.options))

	if not global_vars.options.fetch:
		parser.print_help()

	if global_vars.options.fetch:
		update_db_tagaya()

if __name__ == "__main__":
	main()
