
import sys, os, re, shutil, subprocess
import urllib.request

usage = """
nuspy.py <titleid>
nuspy.py <titleid> <country>
nuspy.py <titleid> <version>
nuspy.py <titleid> <country> <version> 
<country> options E/J/U
<version> is base10 number and can be found at:
		  http://wiiubrew.org/wiki/Title_database
Titleid is a mandatory field and can be used with the dash or without.
Version and Country are optional and default to newest and USA respectively.
"""

#Check argument for title, country and version...set defaults
if len(sys.argv) < 2 or len(sys.argv) > 4:
	print(usage)
	exit()
	
else:
	if len(sys.argv) == 2:
		titleid = sys.argv[1]
		if titleid.find('-') == -1:
			titleid = titleid[:8] + '-' + titleid[8:]
			titleid = titleid.lower()
		elif titleid.find('-') > 0:
			titleid = titleid.lower()
		else:
			print(usage)
			exit()

		c = 'USA'
		ver = None
  
	elif len(sys.argv) == 3:
		titleid = sys.argv[1]
		if titleid.find('-') == -1:
			titleid = titleid[:8] + '-' + titleid[8:]
			titleid = titleid.lower()
		elif titleid.find('-') > 0:
			titleid = titleid.lower()
		else:
			print(usage)
			exit()
            
		if len(sys.argv[2]) == 1 and sys.argv[2].isalpha():
			c = sys.argv[2].lower()
			if c == 'u':
				c = 'USA'
			elif c == 'j':
				c = 'JPN'
			elif c == 'e':
				c = 'EUR'
			ver = None
		elif sys.argv[2].isdigit():
			ver = str(sys.argv[2])
			c = 'USA'
		else:
			print(usage)
			exit()
        
	elif len(sys.argv) == 4:
		titleid = sys.argv[1]
		if titleid.find('-') == -1:
			titleid = titleid[:8] + '-' + titleid[8:]
			titleid = titleid.lower()
		elif titleid.find('-') > 0:
			titleid = titleid.lower()
		else:
			print(usage)
			exit()
            
		if len(sys.argv[2]) == 1 and sys.argv[2].isalpha():
			c = sys.argv[2].lower()
			if c == 'u':
				c = 'USA'
			elif c == 'j':
				c = 'JPN'
			elif c == 'e':
				c = 'EUR'
		elif sys.argv[2].isdigit():
			print(usage)
			exit()

		if  sys.argv[3].isdigit():
			ver = str(sys.argv[3])
		else:
			print(usage)
			exit()

#Variables
repover = ''
filedir = os.getcwd()
selectedtitle = ''


# Find titles from REPO

def findTitle(logf, titleid):
	log = urllib.request.urlopen(repo + r'/' + logf)
	log = log.read().decode(encoding="utf-8")
	
	m = re.search('(?ms)\* DETAILED DUMPS \*(.*).*\* MESSAGE LOG \*', log)
	
	tid = ''
	version = ''
	size = ''
	content = []
		
	if m != None:
		dump = m.group(1).split('\n')
		#print("Checking Lines:", len(dump))
		for i in range(len(dump)):
			if dump[i].startswith(" Title ID:"):
				tid = dump[i][11:].lower()
				if dump[i+1].startswith(" Version:"):
					version = str(int(dump[i+1][10:],16))
					size = dump[i+2][7:]
				elif dump[i+1].startswith(" Size:"):
					version = 1
					size = dump[i+1][7:]
				#print("Found: ", tid, version)
				if tid == titleid:
					print("Located TitleID: ", tid)
					print("Version: ", version)
					print("Size: ", size)
					if dump[i+11].startswith("  Contents:"):
						x = i + 13
						for j in range(len(dump)-x):
							#print(dump[x+j])
							titleline = dump[x+j]
							id = titleline[3:11]
							titlenum = titleline[12:16].strip()
							type = titleline[18:25].strip()
							size = titleline[26:35].strip()
							hash = titleline[40:].strip()
							#print(id,titlenum,type,size)
							content.append(id)
							if dump[x+j+1].startswith(" TMD"):
								break					
					if dump[i+12].startswith("  Contents:"):
						x = i + 14
						for j in range(len(dump)-x):
							print(dump[x+j])
							titleline = dump[x+j]
							id = titleline[3:11]
							titlenum = titleline[12:16].strip()
							type = titleline[18:25].strip()
							size = titleline[26:35].strip()
							hash = titleline[40:].strip()
							#print(id,titlenum,type,size)
							content.append(id)
							if dump[x+j+1].startswith(" TMD"):
								break
					if dump[i+13].startswith("  Contents:"):
						x = i + 15
						for j in range(len(dump)-x):
							titleline = dump[x+j]
							id = titleline[3:11]
							titlenum = titleline[12:16].strip()
							type = titleline[18:25].strip()
							size = titleline[26:35].strip()
							hash = titleline[40:].strip()
							#print(id,titlenum,type,size)
							content.append(id)
							if dump[x+j+1].startswith(" TMD"):
								break

					return tid, version, content
	return None

def downloadTitle(selectedtitle):
	thistit, ver, titles = selectedtitle
	thistit = ''.join(thistit.split('-')).lower()
	titledir = filedir + r'/' + thistit
	countrydir = titledir + r'/' + c
	verdir = countrydir + r'/' + ver
    
	if os.path.isdir(titledir):
		os.chdir(titledir)
	else:
		os.mkdir(titledir)
		os.chdir(titledir)
	if os.path.isdir(countrydir):
		os.chdir(countrydir)
	else:
		os.mkdir(countrydir)
		os.chdir(countrydir)
	if os.path.isdir(verdir):
		os.chdir(verdir)
		if len(os.listdir(os.getcwd())) > 0:
			os.chdir('..')
			shutil.rmtree(verdir)
	os.mkdir(verdir)
	os.chdir(verdir)
	
		
    
	print("Downloading", len(titles), "titles from NUS")
	for t in titles:
		print("Downloading: ", t)
		url = r'http://nus.cdn.shop.wii.com/ccs/download/' + thistit + '/' + t
		#	print("URL: ", url)
		f= bytes(urllib.request.urlopen(url).read())
		open(verdir + r'/' + t, 'wb' ).write(f)

	if ver != None:
		print(r'Downloading TMD tmd.' + ver)
		tmdfile = urllib.request.urlopen(r'http://nus.cdn.shop.wii.com/ccs/download/' + thistit + '/tmd.' + ver)
	else:
		tmdfile = urllib.request.urlopen(r'http://nus.cdn.shop.wii.com/ccs/download/' + thistit + '/tmd')
	
	print(r'Downloading cetk')
	cetk = urllib.request.urlopen(r'http://nus.cdn.shop.wii.com/ccs/download/' + thistit + '/cetk')

	open(verdir + r'/' + 'tmd', 'wb').write(tmdfile.read())
	open(verdir + r'/' + 'cetk', 'wb').write(cetk.read())
	os.chdir(filedir)
	return verdir
   
    
print("""
Data is pulled from Wii U Impersonator!
Thanks to fail0verfl0w for their efforts!
Thanks WulfySytlez and Bug_Checker_ for their patience
Coded by Onion_Knight
""")



if titleid.startswith('0005'):
	repover = 'wiiu'
elif titleid.startswith('00000007') or \
	 titleid.startswith('00070002') or \
	 titleid.startswith('00070008'):
	repover = 'vwii'
elif titleid.startswith('00000001') or \
	 titleid.startswith('00010001') or \
	 titleid.startswith('00010002') or \
	 titleid.startswith('00010005') or \
	 titleid.startswith('00010008'):
	repover = 'wii'

if repover == 'wii':
		print("nuspy doesn't support wii title downloads")
		exit()
	
repo = r'http://wii.marcan.st/wiimpersonator/reports/' + repover + r'/' + c + r'/'

print("Starting log find: ", titleid)
print("Using Repo:", repo)



#Grab Logs from Wii U Impersonator Repo

wiiulogs = urllib.request.urlopen(repo)
logs = wiiulogs.read().decode(encoding="utf-8")
logs = re.findall('(?m)\<a href\=\"(.*log)?\"', logs)
logs.reverse()

#Loop through logs finding our Title

print("\n")
found = False
for l in logs:
	print("Searching log:", l)
	m = findTitle(l, titleid.strip())
	if m != None:
		found = True
		#print("FOUND: ",m[0], "VER:",m[1])	
		if ver != None:
			if m[1].strip() == ver.strip():
				print("FOUND", m[0], m[1])
				selectedtitle = m
				break
		elif ver == None :
			print("No Version Detected")
			selectedtitle = m
			break

if found == False:
	print("Failed to locate title")
	exit()
   
#Download Selected title and title IDs
vdir = downloadTitle(selectedtitle)

if repover is 'wiiu':
	os.chdir(vdir)
	subprocess.call(['CDecrypt.exe', 'tmd', 'cetk', '../../../ckey.bin'])
	os.chdir(filedir)
