
import sys, os, shutil, pytmd, struct, functools
import urllib.request
try:
	#Completely borrowed the Cyrpto.Cipher idea from 
	#zecoxao from gbatemp.  His documentation of it really
	#made it easy.  I was using the aes implementation included
	#but its painfully slow
	from Crypto.Cipher import *
	useCrypto = True
except ImportError:
	import aes
	useCrypto = False


usage = """
	nuspy.py <titleid>
	nuspy.py <titleid> <country>
	nuspy.py <titleid> <version>
	nuspy.py <titleid> <country> <version> 
	<country> options E/J/U  
		****DEPRECATED SINCE I NO LONGER USE THE WII IMPERSONATOR 
		****AND DON'T KNOW WHERE THE COUNTRY CHECK IS IN THE TMD. 
		****IF YOU WANT A SPECIFIC COUNTRY CHECK THE LOGS AT THE 
		****WII IMPERSONATOR AND SPECIFY THE TITLE AND VER
		****http://wii.marcan.st/wiimpersonator/reports/wiiu/
	<version> is base10 number and can be found at:
		****http://wiiubrew.org/wiki/Title_database
	Titleid is a mandatory field,used with or without the dash.
	Version is optional and defaults to newest.
	"""

credits = """
	Data is no longer pulled from Wii U Impersonator! Yay!
	Data is now directly downloaded and parsed from the TMD ticket
	Thanks to fail0verfl0w for their efforts! Still thanks to them!
	Thanks WulfySytlez, Bug_Checker_, NWPlayer123. 
	Especially to Crediar for the CDecrypt source that was easy to 
	read, informative and documented well enough!
	Coded by Onion_Knight
	"""

#Check argument for title, country and version...set defaults
def getArgs():
	if len(sys.argv) < 2 or len(sys.argv) > 4:

		print(usage)
		exit()
	else:
		if len(sys.argv) == 2:
			titleid = sys.argv[1]
			if titleid.find('-') == -1:
				if len(titleid) != 16:
					print(usage)
				else:
					titleid = titleid.lower()
			elif titleid.find('-') > 0:
				titleid = ''.join(titleid.split('-'))
				titleid = titleid.lower()
			else:
				print(usage)
				exit()

			c = 'USA'
			ver = None
			
			return [titleid,c,ver]
		
		elif len(sys.argv) == 3:
			titleid = sys.argv[1]
			if titleid.find('-') == -1:
				if len(titleid) != 16:
					print(usage)
				else:
					titleid = titleid.lower()
			elif titleid.find('-') > 0:
				titleid = ''.join(titleid.split('-'))
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
			return [titleid,c,ver]
		elif len(sys.argv) == 4:
			titleid = sys.argv[1]
			if titleid.find('-') == -1:
				if len(titleid) != 16:
					print(usage)
				else:
					titleid = titleid.lower()
			elif titleid.find('-') > 0:
				titleid = ''.join(titleid).split('-')
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
			return [titleid,c,ver]

#Variables
nus = r'http://nus.cdn.shop.wii.com/ccs/download/' 

#KEYS
etkey_hex =''
ckey_hex = ''
tidkey_hex = ''
dtkey_hex =''
etkey =[]			#Encrypted Title Key
ckey =[]			#Common Key
tkey_iv = []		#Title Key IV
dtkey = [] 			#Decrypted Title Key
		

def downloadTMD(titleid,ver,fileid):
	
	print("Downloading TMD for:",titleid)

	try:
		if fileid == 'tmd' and ver == None:									#If No version selected currently, its cool well get it when we grab TMD file
			tmdurl = nus + titleid + r'/tmd'
			tmdfile = bytes(urllib.request.urlopen(tmdurl).read())
			#print(dir(tmdfile))
			tmdver = str((tmdfile[0x1DC] << 8) + tmdfile[0x1DD])						#TMD ver is at offset 0x1DC and is two bytes in length.  So we pack them together
			print("No Version Selected, Found:",tmdver)
			os.makedirs(tmdver, exist_ok = True)													#Create a new tmd version directory and get there.
			os.chdir(tmdver)
			outf =  open('tmd', r'wb')
			outf.write(tmdfile)
		elif fileid == 'tmd' and ver != None:									#In this instance we have version specified so we are n the right directory, yay small block
			tmdurl = urllib.request.urlopen(nus + titleid + r'tmd.'+ver)
			tmdfile = urllib.request.urlopen(tmdurl).read()
			print("Writing TMD to file")
			outf =  open('tmd', r'wb')
			outf.write(tmdfile)
		outf.close()
		return 
	except Exception as e:
		print("Exception:",e)
		exit()
# Find titles from REPO

def parseTMD():
	if os.path.isfile('tmd'):
		tmd = pytmd.TMD_PARSER('tmd')
		tmd.ReadContent()
		print("Parsing TMD for:", tmd.tmd_title_id)
		print("Titles found:")
		titles = []
		for title in tmd.tmd_contents:
			print("ID:", title.id, "Index:", title.index, "Type:", title.type, "Size:", title.size)
			titles.append(title.id)
		return (tmd,titles)
	else:
		print("TMD File Not Found!")
		exit()
	
def downloadTitles(titleid,titles):
		
	for title in titles:
		url = nus + titleid + r'/' + title
		if (os.path.isfile(title)):
			print("Cached:", title)
		else:
			print("Downloading:", title)
			f = bytes(urllib.request.urlopen(url).read())
			open(title, 'wb').write(f)
	f = bytes(urllib.request.urlopen(nus + titleid + r'/cetk').read())
	print("Downloading cetk")
	open('cetk', 'wb').write(f)
	return

def loadTitleKeys(rootdir):
	"""
	Opens cetk, tmd, and the common key to decrypt the title key found in cetk.
	Basically this is a python implementation of Crediar's CDecrypt.  He gets 
	full credit for both demonstrating how this looks and where the encrypted Title ID.
	"""
	cetkf = open('cetk', 'rb')
	cetkf.seek(0x1bf,0)
	cetk = cetkf.read(16)
	ckey = open(os.path.join(rootdir, 'ckey.bin'), 'rb').read(16)
	
	tidkeyf = open('tmd', 'rb')
	tidkeyf.seek(0x18c, 0)
	tidkey = tidkeyf.read(8) 
	tidkey += b'\x00'*8
	
	cetkf.close()
	tidkeyf.close()
	
	etkey_hex = ('%016x' % struct.unpack('>QQ',cetk)[0]) + ('%016x' % struct.unpack('>QQ', cetk)[1])
	ckey_hex = ('%016x' % struct.unpack('>QQ', ckey)[0]) + ('%016x' % struct.unpack('>QQ', ckey)[1])
	tidkey_hex = ('%016x' % struct.unpack('>QQ', tidkey)[0]) + ('%016x' % struct.unpack('>QQ', tidkey)[1])
	
	
	etkey =  list(struct.unpack('>BBBBBBBBBBBBBBBB',cetk))
	ckey  =  list(struct.unpack('>BBBBBBBBBBBBBBBB',ckey))
	tkey_iv = list(struct.unpack('>BBBBBBBBBBBBBBBB',tidkey))
	return [etkey,ckey,tkey_iv],[etkey_hex,ckey_hex,tidkey_hex]

def decryptData(keys):
	data,d_crypt_key,iv_key = keys
	
	decrypted = ''
	if useCrypto:
		try:
			dkey = bytes(d_crypt_key)
			iv = bytes(iv_key)
			aes_crypto = AES.new(dkey,AES.MODE_CBC, iv)
			decrypted = aes_crypto.decrypt(bytes(data))
			
			decrypted =''.join(list(map(chr,[byte for byte in decrypted])))
		except Exception as e:
			print(e)	
	else:
		try:
			moo = aes.AESModeOfOperation()
			mode = aes.AESModeOfOperation.modeOfOperation["CBC"]
			keysize = 16	
			

			decrypted = moo.decrypt(data, None, mode, d_crypt_key, keysize, iv_key)
		except Exception as e:
			print(e)
	return decrypted 

def decryptTitleKey(keys):
	decrypted = decryptData(keys)
	dtkey_packed = 0
	dtkey  = list(map(ord,list(decrypted)))
	
	for val in dtkey:
		dtkey_packed += val
		dtkey_packed = dtkey_packed << 8
	dtkey_packed = dtkey_packed >> 8
	dtkey_hex = ('%016x' % dtkey_packed)
	
	#print("Encrypted Title Key:",data)
	#print("IV:", iv_key)
	#print("Decrypted Title Key:", dtkey_hex.upper())
	return dtkey,dtkey_hex 	
	
def loadContent(tmd,ckey,dkey):
	title = tmd.tmd_contents[0].id
	size = tmd.tmd_contents[0].size
	
	contentf = open(title, 'rb').read()
	contentf = list(contentf)
	
	iv_key = list(map(ord, '\x00'*16))
	
	data = decryptData((contentf,dkey,iv_key))
	data = list(map(ord, list(data)))

	
	fst = pytmd.FST_PARSER(data)
	fst.ReadFST()
	fst.GetFileListFromFST()
	
	return fst
	
def extractFiles(filedir,fst,tmd,ckey,dkey):

	fe = fst.fe_entries
	
	rootdir = os.path.join(filedir, tmd.tmd_title_id, str(int(tmd.tmd_title_version,16)))
	dir_register = {}
	os.chdir(rootdir)	
	
	
	rd = fe[0].parent
	rootpath = os.path.join(rootdir, rd)
	if os.path.isdir(rootpath):
		shutil.rmtree(rd)
	
	os.chdir(rootdir)
	os.mkdir(rd)
	os.chdir(rd)
	dir_register[rd] = os.getcwd()
	
	print("Root set to:",rootpath)

	for file in fe[1:]:
		if file.type == 1:
			par = file.parent
			mydir = file.fn
			nx = file.next
			cwd = os.getcwd()
			if par == rd:
				os.chdir(rootpath)
			if os.path.isdir(mydir):
				os.mkdir(mydir)
				os.chdir(mydir)
				if dir_register.get(mydir) is None:
					dir_register[dir] = os.getcwd()
					print(" Created:",os.getcwd())
			if os.getcwd().endswith(par):
				os.mkdir(mydir)
				os.chdir(mydir)
				if dir_register.get(mydir) is None:
					dir_register[mydir] = os.getcwd()
					print(" Created:",os.getcwd())
			else:
				if dir_register.get(par):
					newdir = dir_register[par]
					os.chdir(newdir)
					os.mkdir(mydir)
					os.chdir(mydir)
					if dir_register.get(mydir) is None:
						dir_register[mydir] = os.getcwd()
						print(" Created:",os.getcwd())
					else:
						if os.getcwd().endswith(par):
							os.mkdir(mydir)
							os.chdir(mydir)
							if dir_register.get(mydir) is None:
								dir_register[mydir] = os.getcwd()
								print(" Created:", os.getcwd())
							else:
								print("Shit!!! I Must have more Recursion! To many layers on this Taco Dip", par, mydir, nx)
		elif file.type == 0:
			fn = file.fn
			offset = file.f_off
			size = file.f_len
			inf = ''	
			for t in tmd.tmd_contents:
				if t.index == file.content_id:
					#print("FOUND:", t.index, "ID:", t.index)
					inf = t.id
			print(" Extracting:", fn, )
			
			iv_key = list(map(ord, '\x00'*16))
			iv_key[1] = file.content_id
			
			data = open(os.path.join(rootdir, inf), 'rb')
			
			#Straight up lifed these calcs from Crediar
			#I can't credit him again for the amazing work he did
			d_size = 0x8000
			
			roffset = offset/ (d_size * d_size)
			soffset = offset - (offset / d_size * d_size)
			#################################################
			data.seek(offset)
			while size > 0:
				encoded = data.read(d_size)
				decoded = decryptData((encoded,dkey,iv_key))
				decoded.lstrip('\x00')
				open(fn, 'wb').write(bytes(decoded, 'utf-8'))
				size -= d_size
			data.close()
			
		else:
			print("SHIT", file.type)

def createPath(titleid,verdir,filedir):
	if os.path.isdir(titleid):
		os.chdir(titleid)
	else:
		os.mkdir(titleid)
		os.chdir(titleid)
	if verdir != None:								#If No version selected currently, its cool well fix it when we grab TMD file
		os.makedirs(verdir, exist_ok = True)
		os.chdir(verdir)
	return
   
def main():

	filedir = os.getcwd()						#Get Current Working Directory  Establishes this as the root directory
	titleid,c,ver =  getArgs()					#Parse CMDLINE Args and get results.  Currently c is deprecated 
	keys = []
	hex_keys = []
	createPath(titleid,ver,filedir)				#Create our FilePath for the NUS Title 
	downloadTMD(titleid,ver,"tmd")				#Download the tmd file
	tmd, titles = parseTMD()
	downloadTitles(titleid,titles)				
	keys,hex_keys = loadTitleKeys(filedir)		#keys: encryptedTitle, common, title_iv
	d_title_key, d_title_key_hex = decryptTitleKey(keys)
	print("Decrypted Title Key:", d_title_key_hex.upper())
	fst = loadContent(tmd,keys[1], d_title_key)
	print("Reading Contents:")
	print("Found " + str((len(fst.fe_entries))) + " files")
	print("Extracting Files...\n")
	extractFiles(filedir,fst,tmd,keys[1], d_title_key)
	


if __name__ == "__main__":
	main()
