#!/usr/bin/env python3
import	bs4
import	argparse
import	re
import	requests
import	sqlite3

def	update_db_wiiubrew():
	#conn = sqlite3.connect(':memory:')
	conn = sqlite3.connect('wiiubrew.db')

	csr = conn.cursor()

	# Create our tables
	csr.execute('''CREATE TABLE IF NOT EXISTS system_titles (
		title_id	TEXT,
		description	TEXT,
		notes		TEXT,
		versions	TEXT,
		region		TEXT,
		PRIMARY KEY (title_id)
		)''')

	csr.execute('''CREATE TABLE IF NOT EXISTS titles (
		title_id	TEXT,
		description	TEXT,
		product_code	TEXT,
		company_code	TEXT,
		notes		TEXT,
		versions	TEXT,
		region		TEXT,
		on_cdn		TEXT,
		PRIMARY KEY (title_id)
		)''')

	csr.execute('''CREATE TABLE IF NOT EXISTS updates (
		title_id	TEXT,
		description	TEXT,
		notes		TEXT,
		versions	TEXT,
		region		TEXT,
		PRIMARY KEY (title_id)
		)''')

	csr.execute('''CREATE TABLE IF NOT EXISTS dlc (
		title_id	TEXT,
		description	TEXT,
		notes		TEXT,
		versions	TEXT,
		region		TEXT,
		PRIMARY KEY (title_id)
		)''')

	conn.commit()

	header = {'User-Agent': 'Mozilla/5.0'} #Needed to prevent 403 error on Wikipedia
	url = "http://wiiubrew.org/wiki/Title_database"
	if not args.quiet:
		print("Fetching %s" % url)
	html = requests.get(url)
	soup = bs4.BeautifulSoup(html.text, 'html.parser')

	# Parse the "system titles" table
	table = soup.find('span', id='0005xxxx:_System_titles').parent.find_next_sibling('table')
	#print(type(table), table)
	headings = table.findAll("th")
	#print(type(headings), headings)
	for row in table.findAll("tr"):
		#print(type(row), row)
		cells = row.findAll("td")
		if len(cells) == 5:
			# Get each cell into separate named vars
			# If the table cell contains any HTML, the cell could contain a list of Tags or NavigableString elements.
			# We can convert it back to text by calling str() on each element.
			# Yes, this could be a nested map(lambda), but I prefer it to be readable/maintainable.
			cell_strings = []
			for i in range(len(cells)):
				s = ''
				for j in range(len(cells[i].contents)):
					s += str(cells[i].contents[j]).strip()
				cell_strings.append(s)
			(title_id, description, notes, versions, region) = cell_strings
			# Do some tidying
			title_id = re.sub('[^0-9A-F]', '', title_id.upper())
			# Strip notes if it only contains '-'
			if notes == '-':
				notes = ''
			#print(title_id, description, notes, versions, region)
			csr.execute("INSERT OR REPLACE INTO system_titles VALUES (?, ?, ?, ?, ?)", (
				title_id,
				description,
				notes,
				versions,
				region,
				))
	conn.commit()

	# Parse the "titles" table
	table = soup.find('span', id='00050000:_eShop_and_disc_titles').parent.find_next_sibling('table')
	#print(type(table), table)
	headings = table.findAll("th")
	#print(type(headings), headings)
	for row in table.findAll("tr"):
		#print(type(row), row)
		cells = row.findAll("td")
		if len(cells) == 8:
			# Get each cell into separate named vars
			cell_strings = []
			for i in range(len(cells)):
				s = ''
				for j in range(len(cells[i].contents)):
					s += str(cells[i].contents[j]).strip()
				cell_strings.append(s)
			(title_id, description, product_code, company_code, notes, versions, region, on_cdn) = cell_strings
			# Do some tidying
			title_id = re.sub('[^0-9A-F]', '', title_id.upper())
			# Strip notes if it only contains '-'
			if notes == '-':
				notes = ''
			csr.execute("INSERT OR REPLACE INTO titles VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (
				title_id,
				description,
				product_code,
				company_code,
				notes,
				versions,
				region,
				on_cdn,
				))
	conn.commit()

	# Parse the "updates" table
	table = soup.find('span', id='0005000E:_eShop_title_updates').parent.find_next_sibling('table')
	#print(type(table), table)
	headings = table.findAll("th")
	#print(type(headings), headings)
	for row in table.findAll("tr"):
		#print(type(row), row)
		cells = row.findAll("td")
		if len(cells) == 5:
			# Get each cell into separate named vars
			cell_strings = []
			for i in range(len(cells)):
				s = ''
				for j in range(len(cells[i].contents)):
					s += str(cells[i].contents[j]).strip()
				cell_strings.append(s)
			(title_id, description, notes, versions, region) = cell_strings
			# Do some tidying
			title_id = re.sub('[^0-9A-F]', '', title_id.upper())
			# Strip notes if it only contains '-'
			if notes == '-':
				notes = ''
			# Strip version strings if they only contain plain version numbers - if they contain text keep as-is
			if len(re.sub('[Vv0-9, -]', '', versions)) == 0:
				versions = ''
			# FIXME - get versions from tagaya.db? or fix after insert?
			csr.execute("INSERT OR REPLACE INTO updates VALUES (?, ?, ?, ?, ?)", (
				title_id,
				description,
				notes,
				versions,
				region,
				))
	conn.commit()

	# Parse the "DLC" table
	table = soup.find('span', id='0005000C:_eShop_title_DLC').parent.find_next_sibling('table')
	#print(type(table), table)
	headings = table.findAll("th")
	#print(type(headings), headings)
	for row in table.findAll("tr"):
		#print(type(row), row)
		cells = row.findAll("td")
		if len(cells) == 5:
			# Get each cell into separate vars
			(title_id, description, notes, versions, region) = map(lambda x: x.string.strip(), cells)
			# Do some tidying
			title_id = re.sub('[^0-9A-F]', '', title_id.upper())
			# Strip notes if it only contains '-'
			if notes == '-':
				notes = ''
			# Strip version strings if they only contain plain version numbers - if they contain text keep as-is
			if len(re.sub('[Vv0-9, -]', '', versions)) == 0:
				versions = ''
			# FIXME - get versions from tagaya.db? or fix after insert?
			csr.execute("INSERT OR REPLACE INTO dlc VALUES (?, ?, ?, ?, ?)", (
				title_id,
				description,
				notes,
				versions,
				region,
				))
	conn.commit()

	conn.close()

def	print_titles():
	conn = sqlite3.connect('wiiubrew.db')

	csr = conn.cursor()

	csr.execute("SELECT * FROM titles ORDER BY title_id")
	rows = csr.fetchall()
	for row in rows:
		#print(type(row), row)
		# Get each cell into separate vars
		(title_id, description, product_code, company_code, notes, versions, region, on_cdn) = row
		# Put the '-' back in the titleid
		title_id = re.sub('(00050000)', '\\1-', title_id.upper())
		print("|-")
		for cell in (title_id, description, product_code, company_code, notes, versions, region, on_cdn):
			print("| %s" % cell)

	conn.close()

def	print_updates():
	conn = sqlite3.connect('wiiubrew.db')

	csr = conn.cursor()

	csr.execute("SELECT * FROM updates ORDER BY title_id")
	rows = csr.fetchall()
	for row in rows:
		#print(type(row), row)
		# Get each cell into separate vars
		(title_id, description, notes, versions, region) = row
		# Put the '-' back in the titleid
		title_id = re.sub('(0005000E)', '\\1-', title_id.upper())
		print("|-")
		for cell in (title_id, description, notes, versions, region):
			print("| %s" % cell)

	conn.close()

def	print_dlc():
	conn = sqlite3.connect('wiiubrew.db')

	csr = conn.cursor()

	csr.execute("SELECT * FROM dlc ORDER BY title_id")
	rows = csr.fetchall()
	for row in rows:
		#print(type(row), row)
		# Get each cell into separate vars
		(title_id, description, notes, versions, region) = row
		# Put the '-' back in the titleid
		title_id = re.sub('(0005000C)', '\\1-', title_id.upper())
		print("|-")
		for cell in (title_id, description, notes, versions, region):
			print("| %s" % cell)

	conn.close()


def	refresh_update_versions():
	conn = sqlite3.connect('wiiubrew.db')

	csr = conn.cursor()

	csr.execute("ATTACH 'tagaya.db' as tagaya")
	csr.execute('''
		INSERT OR REPLACE INTO updates (title_id, description, notes, versions, region)
		SELECT title_id, description, notes, GROUP_CONCAT(title_version, ", "), region
		FROM updates LEFT JOIN tagaya.title_info USING (title_id) WHERE versions = '' GROUP BY title_id
		''')
	csr.execute("DETACH tagaya")
	conn.commit()
	conn.close()

def	main():
	# Make our CLI options global so we don't have to pass them around.
	global args

	# The "new, improved" argparse is fucked.
	# It does everything well, except parse arguments.
	# Options, it does ok. Arguments? Not. At. All.
	# And it is not even close to being compatible with optparse

	parser = argparse.ArgumentParser(description='wiiubrew DB tool')
	parser.add_argument('-q',	'--quiet',	dest='quiet',		help='quiet output',				action='store_true',		default=False)
	parser.add_argument('-f',	'--fetch',	dest='fetch',		help='Fetch current tables from wiiubrew',	action='store_true',		default=False)
	parser.add_argument('-r',	'--refresh',	dest='refresh',		help='Refresh "updates" versions from tagaya',	action='store_true',		default=False)
	parser.add_argument('-t',	'--titles',	dest='titles',		help='Print "titles" table',			action='store_true',		default=False)
	parser.add_argument('-u',	'--updates',	dest='updates',		help='Print "updates" table',			action='store_true',		default=False)
	parser.add_argument('-d',	'--dlc',	dest='dlc',		help='Print "dlc" table',			action='store_true',		default=False)

	args = parser.parse_args()
	#print(type(vars(args)), vars(args))

	if args.fetch:
		update_db_wiiubrew()

	if args.refresh:
		refresh_update_versions()

	if args.titles:
		print_titles()

	if args.updates:
		print_updates()

	if args.dlc:
		print_dlc()


if __name__ == "__main__":
	main()
