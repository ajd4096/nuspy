#!/usr/bin/env python3
import argparse
import bs4
import os
import requests
import sqlite3

# My modules
import	nuspy.global_vars	as global_vars

DEBUG_LEVEL      = 3

def	update_db_samurai(regions, nids, tids):
	conn = sqlite3.connect('nuspy-samurai.db')
	csr = conn.cursor()

	# Create our tables
	csr.executescript( '''
		CREATE TABLE IF NOT EXISTS id_pair (
			title_id	TEXT,
			ns_uid		TEXT,
			PRIMARY KEY (title_id, ns_uid)
		);
		CREATE INDEX IF NOT EXISTS idp_nid ON id_pair (ns_uid, title_id);
		''' )
	conn.commit()

	csr.executescript( '''
		CREATE TABLE IF NOT EXISTS title_xml (
			ns_uid		TEXT,
			region		TEXT,
			xml		TEXT,
			PRIMARY KEY (ns_uid, region)
		);
		''' )
	conn.commit()

	nid_list = []

	# If the user specified NIDs, use them
	if nids and len(nids):
		if global_vars.options.verbose:
			print("Checking NIDs")
		nid_list = nids

	# If the user specified TIDs, look up the matching NIDs
	if tids and len(tids):
		if global_vars.options.verbose:
			print("Checking TIDs")
		for tid in tids:
			if global_vars.options.verbose:
				print("Checking title_id %s" % tid)

			# See if we already have the id_pair for this tid
			csr.execute('''SELECT ns_uid FROM id_pair WHERE title_id = ?''', [tid])
			data = csr.fetchone()
			if data:
				# Add the nid to our list
				nid = int(data[0])
				nid_list.append(nid)
			else:
				# We do not have this value, get the ns_uid from ninja
				# ninja requires a client-side SSL certificate+key
				# You can get these from 3DS 0004001b00010002 or WiiU 0005001B10054000
				url="https://ninja.ctr.shop.nintendo.net/ninja/ws/titles/id_pair?title_id[]=" + tid
				if global_vars.options.verbose:
					print("Fetching id_pair %s" % url)
				html = requests.get(url,
					headers = {'User-Agent': 'WiiU/PBOS-1.1'},
					cert=('ninja-common-1.crt', 'ninja-common-1.key'),
					verify='nintendo_cert_bundle.pem')
				if html:
					soup = bs4.BeautifulSoup(html.text, "html.parser")
					title_id_pair_list = soup.findAll("title_id_pair")
					# We asked for one value, we should get one result
					if len(title_id_pair_list) == 1:
						for title_id_pair in title_id_pair_list:
							nid = title_id_pair.findAll("ns_uid")[0].string
							tid2 = title_id_pair.findAll('title_id')[0].string
							assert(tid == tid2)
							# Add the id_pair to our table
							csr.execute("INSERT OR REPLACE INTO id_pair VALUES (?, ?)", (tid, nid))
							# Add the nid to our list
							nid_list.append(nid)

	# If the user didn't specify any NIDs or TIDs, get every NID for each region
	if (not tids or len(tids) == 0) and (not nids or len(nids) == 0):
		if global_vars.options.verbose:
			print("Fetching all NIDs")
		# For each region...
		for region in regions:
			# Get the country code
			# The WiiU is much simpler than the 3DS
			if region == 'JAP':
				cc = 'JP'
			elif region == 'USA':
				cc = 'US'
			elif region == 'EUR':
				cc = 'GB'
			else:
				print("Unknown region '%s'" % region)
				continue

			# Get the list of NIDs from samurai
			limit = 100
			for offset in range(0, 10000, limit):
				url="https://samurai.ctr.shop.nintendo.net/samurai/ws/{CC}/titles?limit={LIMIT}&offset={OFFSET}".format(CC=cc, LIMIT=limit, OFFSET=offset)
				if global_vars.options.verbose:
					print("Fetching title list %s" % url)
				html = requests.get(url,
					headers = {'User-Agent': 'WiiU/PBOS-1.1'},
					verify='nintendo_cert_bundle.pem')
				if html:
					soup = bs4.BeautifulSoup(html.text, "html.parser")
					title_node_list = soup.findAll("title")
					for title_node in title_node_list:
						nid = title_node.get('id')
						nid_list.append(nid)
					# If we got fewer than the limit we requested, we have hit the end
					if len(title_node_list) < limit:
						break

	if global_vars.options.verbose >= DEBUG_LEVEL:
		for nid in nid_list:
			print("%s" % nid)

	# Now we have a full list of NIDs, fetch the XML for each NID for each region
	for region in regions:
		# Get the country code
		# The WiiU is much simpler than the 3DS
		if region == 'JAP':
			cc = 'JP'
		elif region == 'USA':
			cc = 'US'
		elif region == 'EUR':
			cc = 'GB'
		else:
			print("Unknown region '%s'" % region)
			continue

		# For each NID...
		for nid in nid_list:
			if global_vars.options.verbose:
				print("Checking ns_uid %s" % nid)

			# See if we already have the id_pair for this nid
			csr.execute('''SELECT title_id FROM id_pair WHERE ns_uid = ?''', [nid])
			data = csr.fetchone()
			if not data:
				# We do not have this value, get the title_id from ninja
				# ninja requires a client-side SSL certificate+key
				# You can get these from 3DS 0004001b00010002 or WiiU 0005001B10054000
				url="https://ninja.ctr.shop.nintendo.net/ninja/ws/titles/id_pair?ns_uid[]=" + nid
				if global_vars.options.verbose:
					print("Fetching id_pair %s" % url)
				html = requests.get(url,
					headers = {'User-Agent': 'WiiU/PBOS-1.1'},
					cert=('ninja-common-1.crt', 'ninja-common-1.key'),
					verify='nintendo_cert_bundle.pem')
				if html:
					soup = bs4.BeautifulSoup(html.text, "html.parser")
					title_id_pair_list = soup.findAll("title_id_pair")
					# We asked for one value, we should get one result
					assert(len(title_id_pair_list) == 1)
					for title_id_pair in title_id_pair_list:
						nid2 = title_id_pair.findAll("ns_uid")[0].string
						assert(nid == nid2)
						tid = title_id_pair.findAll('title_id')[0].string
						csr.execute("INSERT OR REPLACE INTO id_pair VALUES (?, ?)", (tid, nid))
						conn.commit()

			# See if we already have the title_xml for this nid
			csr.execute('''SELECT ns_uid FROM title_xml WHERE ns_uid = ? AND region = ?''', [nid, region])
			data = csr.fetchone()
			if not data:
				# We do not have this value, get the title XML from samurai
				url="https://samurai.ctr.shop.nintendo.net/samurai/ws/{CC}/title/{NID}".format(CC=cc, NID=nid)
				if global_vars.options.verbose:
					print("Fetching title info %s" % url)
				html = requests.get(url,
					headers = {'User-Agent': 'WiiU/PBOS-1.1'},
					verify='nintendo_cert_bundle.pem')
				if html:
					soup = bs4.BeautifulSoup(html.text, "html.parser")
					title_list = soup.findAll("title")
					# We asked for one value, we should get one result
					assert(len(title_list) == 1)
					# Save the xml in our table
					csr.execute("INSERT OR REPLACE INTO title_xml VALUES (?, ?, ?)", (nid, region, html.text))
					conn.commit()

	conn.close()

def	main():
	parser = argparse.ArgumentParser(description='samurai/ninja DB scraping tool')
	parser.add_argument('-v',	'--verbose',	dest='verbose',		help='verbose output',				action='count',		default=0)
	parser.add_argument('-r',	'--region',	dest='regions',		help='Use REGION',				metavar='REGION',	nargs='+')
	parser.add_argument('-n',	'--nid',	dest='nids',		help='Download information for NID',		metavar='NID',		nargs='+')
	parser.add_argument('-t',	'--tid',	dest='tids',		help='Download information for TID',		metavar='TID',		nargs='+')

	global_vars.options = parser.parse_args()
	#print(type(vars(global_vars.options)), vars(global_vars.options))

	if not global_vars.options.regions and not global_vars.options.nids and not global_vars.options.tids:
		parser.print_help()
		exit(0)

	if not global_vars.options.regions or global_vars.options.regions == ['all']:
		global_vars.options.regions = ['JAP', 'USA', 'EUR']
	#print(type(vars(global_vars.options)), vars(global_vars.options))

	update_db_samurai(global_vars.options.regions, global_vars.options.nids, global_vars.options.tids)


if __name__ == "__main__":
	main()
