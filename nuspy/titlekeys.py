#!/usr/bin/env python3.5

import argparse
import binascii
import bs4
import calendar
import csv
import functools
import hashlib
import os
import re
import requests
import shutil
import sqlite3
import struct
import sys
import time
import urllib.request
import warnings

# My modules
import nuspy.global_vars	as global_vars

try:
	# current versions of pycrypto depend on gmp >= 5, but RHEL6 only has gmp 4.3
	# Using the older gmp could have a timing attack vulnerability if you are doing anything security related.
	# We don't care about the timing attack, so we can safely suppress the warning.
	warnings.filterwarnings("ignore", message="Not using mpz_powm_sec.  You should rebuild using libgmp >= 5 to avoid timing attack vulnerability.")

	#Completely borrowed the Cyrpto.Cipher idea from
	#zecoxao from gbatemp.  His documentation of it really
	#made it easy.  I was using the aes implementation included
	#but its painfully slow

	from Crypto.Cipher import *
	useCrypto = True
except ImportError:
	import nuspy.aes as aes
	useCrypto = False

def	update_db_titlekeys():

	#conn = sqlite3.connect(':memory:')
	conn = sqlite3.connect('nuspy-titlekeys.db')

	csr = conn.cursor()

	# Create our tables
	csr.execute('''CREATE TABLE IF NOT EXISTS title_keys (
		name		TEXT,
		region		TEXT,
		size_rpx	REAL,
		size_rpls	REAL,
		size_content	REAL,
		key_wud		TEXT,
		key_nus		TEXT,
		game_id		TEXT,
		languages	TEXT,
		title_id	TEXT,
		version		INTEGER,
		comment		TEXT,
		PRIMARY KEY (title_id)
		)''')

	conn.commit()


	url = "https://docs.google.com/spreadsheets/d/1l427nnapxKEUBA-aAtiwAq1Kw6lgRV-hqdocpKY6vQ0/export?format=csv&gid=923297102"

	if global_vars.options.verbose:
		print("Fetching %s" % url)
	html = requests.get(url)
	if html:
		# Using DictReader isn't much of an advantage - if the table headers change the code needs fixing anyway :|
		reader = csv.DictReader(html.text.splitlines())
		for line in reader:
			#print(type(line), line)
			csr.execute("INSERT OR IGNORE INTO title_keys VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
				line['Game'],
				line['Region'],
				line['RPX (MBs)'],
				line['RPLs (MBs)'],
				line['Content (GBs)'],
				line['WUD key'],
				line['NUS key (encrypted)'],
				line['Game ID'],
				line['Languages'],
				line['Title ID'],
				line['Version'],
				line['Comment'],
				))
		conn.commit()
	# Get the number of rows in the table
	csr.execute('''SELECT COUNT(*) FROM title_keys''')
	rowcount = int(csr.fetchone()[0])
	if global_vars.options.verbose:
		print("Row count %d" % rowcount)
	# Close the DB connection
	conn.close()

def	get_ekey_from_titlekeys(titleid):
	# Get the version from our DB
	conn = sqlite3.connect('nuspy-titlekeys.db')
	csr = conn.cursor()
	csr.execute('''SELECT key_nus FROM title_keys WHERE title_id = ?''', [titleid])
	data = csr.fetchone()
	conn.close()
	if data:
		return data[0]

def	main():
	parser = argparse.ArgumentParser(description='titlekeys DB tool')
	parser.add_argument('-v',	'--verbose',	dest='verbose',		help='verbose output',				action='count',			default=0)
	parser.add_argument('-f',	'--fetch',	dest='fetch',		help='Fetch current titlekeys tables G',	action='store_true',		default=False)

	global_vars.options = parser.parse_args()
	#print(type(vars(global_vars.options)), vars(global_vars.options))

	if not global_vars.options.fetch:
		parser.print_help()

	if global_vars.options.fetch:
		update_db_titlekeys()

if __name__ == "__main__":
	main()
