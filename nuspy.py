#!/usr/bin/env python3

import sys, os, shutil, pytmd, struct, functools
import binascii
import hashlib
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
		

def downloadTMD(titledir, titleid, ver):
	cache_dir = os.path.join(titledir, 'cache')
	os.makedirs(cache_dir, exist_ok = True)
	
	print("Downloading TMD for:",titleid)

	try:
		if ver == None:									#If No version selected currently, its cool well get it when we grab TMD file
			tmdurl = nus + titleid + r'/tmd'
			tmdfile = bytes(urllib.request.urlopen(tmdurl).read())
			#print(dir(tmdfile))
			tmdver = str((tmdfile[0x1DC] << 8) + tmdfile[0x1DD])						#TMD ver is at offset 0x1DC and is two bytes in length.  So we pack them together
			print("No Version Selected, Found:",tmdver)
			outf =  open(os.path.join(cache_dir, 'tmd'), r'wb')
			outf.write(tmdfile)
			outf.close()
			ver = tmdver

		if ver != None:									#In this instance we have version specified so we are n the right directory, yay small block
			tmdurl = nus + titleid + r'/tmd.'+ver
			tmdfile = urllib.request.urlopen(tmdurl).read()
			print("Writing TMD to file")
			outf =  open(os.path.join(cache_dir, 'tmd.'+ver), r'wb')
			outf.write(tmdfile)
			outf.close()

		print("Downloading cetk")
		f = bytes(urllib.request.urlopen(nus + titleid + r'/cetk').read())
		open(os.path.join(cache_dir, 'cetk'), 'wb').write(f)

		return ver

	except Exception as e:
		print("Exception:",e)
		exit()
# Find titles from REPO

def parseTMD(titledir, ver):
	cache_dir = os.path.join(titledir, 'cache')
	tmd_path = os.path.join(cache_dir, 'tmd.' +ver)
	if os.path.isfile(tmd_path):
		tmd = pytmd.TMD_PARSER(tmd_path)
		tmd.ReadContent()
		print("Parsing TMD for:", tmd.tmd_title_id)
		print("Titles found:")
		for title in tmd.tmd_contents:
			print("ID:", title.id, "Index:", title.index, "Type:", title.type, "Size:", title.size)
		return tmd
	else:
		print("TMD File Not Found!")
		exit()
	
def downloadTitles(titledir, tmd):
	cache_dir = os.path.join(titledir, 'cache')
	for content in tmd.tmd_contents:
		url = nus + tmd.tmd_title_id + r'/' + content.id
		filename = os.path.join(cache_dir, content.id)
		# If we don't have the file or it is too small, download it
		# FIXME: there are some titles where the file is larger than the tmd content.size.
		# For example: 0005000e1010fc00/00000001 is 32784 bytes, but content.size says 32769
		if (os.path.isfile(filename) and os.path.getsize(filename) >= content.size):
			print("Cached:", url)
		else:
			print("Downloading:", url)
			urllib.request.urlretrieve(url, filename)

		# Fetch the .h3 files
		# We don't know the size, but they are only small (20 or 40 bytes)
		if (content.type & 0x02):
			url += '.h3'
			filename += '.h3'
			if (os.path.isfile(filename)):
				print("Cached:", url)
			else:
				print("Downloading:", url)
				urllib.request.urlretrieve(url, filename)

	return

#
# Decrypt 00000000 -> 00000000.plain
#
def decryptContentFiles(titledir, tmd, ckey, dkey):
	cache_dir = os.path.join(titledir, 'cache')
	for content in tmd.tmd_contents:
		filename = os.path.join(cache_dir, content.id)

		if (os.path.isfile(filename + '.plain') and os.path.getsize(filename + '.plain') >= content.size):
			print("Cached: %s.plain" % filename)
		else:
			print("Decrypting: %s" % filename)

			iv_key = list(map(ord, '\x00'*16))
			iv_key[0] = content.index >> 8
			iv_key[1] = content.index

			# Read the encrypted file
			encrypted_data = open(filename, 'rb').read()

			# Pad up to 16
			if ((len(encrypted_data) % 16) != 0):
				encrypted_data += b'\x00' * (16 - (len(encrypted_data) % 16))

			decrypted_data = decryptData((encrypted_data, dkey, iv_key)).encode('latin-1')

			# Write the decrypted file.plain
			open(filename + ".plain", "wb").write(decrypted_data)

#
# Validate hashes of title.plain, title.h3
# FIXME - verify the hashes in the .h3 file
#
# The .h3 seems to be 1 or more 20-byte hash, with one hash for each 256M?
# The hashes are not stored in the content file (encrypted or plain)
# The hashes do not match any N * 1MB chunk starting from offset 0 of the content file (encrypted or plain)
#
def verifyContentHashes(titledir, tmd):
	cache_dir = os.path.join(titledir, 'cache')
	failed = False
	for content in tmd.tmd_contents:
		filename = os.path.join(cache_dir, content.id)

		# If the type has a .h3, the TMD hash is of the .h3 file
		# Otherwise it is the hash of the decrypted contents file
		if (content.type & 0x02):
			filename += ".h3"
		else:
			filename += ".plain"

		print("Checking %s" % filename)

		# Only checksum the content.size
		found = hashlib.sha1(open(filename, "rb").read()[:content.size]).hexdigest()

		expected = binascii.hexlify(content.sha1_hash[:20]).decode('utf-8')

		if (found != expected):
			print("Checksum failed for %s!" % filename)
			print("Expected: %s" % expected)
			print("Found: %s" % found)
			failed = True
	if failed:
		exit(1)


def loadTitleKeys(titledir, ver, ckey):
	cache_dir = os.path.join(titledir, 'cache')
	"""
	Opens cetk, tmd, and the common key to decrypt the title key found in cetk.
	Basically this is a python implementation of Crediar's CDecrypt.  He gets 
	full credit for both demonstrating how this looks and where the encrypted Title ID.
	"""
	cetkf = open(os.path.join(cache_dir, 'cetk'), 'rb')
	cetkf.seek(0x1bf,0)
	cetk = cetkf.read(16)

	tidkeyf = open(os.path.join(cache_dir, 'tmd.' +ver), 'rb')
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
	
def loadContent(titledir, tmd,ckey,dkey):
	cache_dir = os.path.join(titledir, 'cache')
	title = tmd.tmd_contents[0].id
	size = tmd.tmd_contents[0].size
	
	contentf = open(os.path.join(cache_dir, title), 'rb').read()
	contentf = list(contentf)
	
	iv_key = list(map(ord, '\x00'*16))
	
	data = decryptData((contentf,dkey,iv_key))
	data = list(map(ord, list(data)))

	
	fst = pytmd.FST_PARSER(data)
	fst.ReadFST()
	fst.GetFileListFromFST()
	
	return fst

def	extractFstDirectory(titledir, fst, tmd, ckey, dkey, currentdir, fstindex):
	cache_dir = os.path.join(titledir, 'cache')
	fe = fst.fe_entries[fstindex]
	print("Creating:  ", currentdir)
	if not os.path.isdir(currentdir):
		os.makedirs(currentdir)

	while (fstindex + 1 < fe.f_len):
		nextfe = fst.fe_entries[fstindex + 1]
		if (nextfe.type == 1 or nextfe.type == 129):
			fstindex = extractFstDirectory(titledir, fst, tmd, ckey, dkey, os.path.join(currentdir, nextfe.fn), fstindex + 1)
		elif (nextfe.type == 0 or nextfe.type == 128):
			extractFstFile(titledir, fst, tmd, ckey, dkey, currentdir, fstindex + 1)
			fstindex += 1
		else:
			print("Unknown FST Entry type %d" % nextfe.type)
			fstindex += 1
	return fstindex

def	extractFstFile(titledir, fst, tmd, ckey, dkey, currentdir, fstindex):
	cache_dir = os.path.join(titledir, 'cache')
	fe = fst.fe_entries[fstindex]

	filename = os.path.join(currentdir, fe.fn)
	print("Extracting:", filename)

	offset = fe.f_off
	size = fe.f_len
	input_filename = ''
	for t in tmd.tmd_contents:
		if t.index == fe.content_id:
			#print("FOUND:", t.index, "ID:", t.index)
			input_filename = os.path.join(cache_dir, t.id + '.plain')

	#print("From", input_filename)
	#print("Offset", offset, "size", size)
	if (not os.path.isfile(input_filename)):
		print('Decrypted file missing', input_filename)
		return

	input_file = open(input_filename, 'rb')
	input_file.seek(offset)

	output_file = open(filename, 'wb')

	# Copy the data in chunks (some files are big compared to memory size)
	chunk_size = 1024 * 1024
	while size > 0:
		data = input_file.read(chunk_size)
		if (size < chunk_size):
			output_file.write(data[:size])
		else:
			output_file.write(data)
		size -= chunk_size
	output_file.close()
	input_file.close()

def	extractFiles(titledir, ver, fst, tmd, ckey, dkey):
	rootdir = os.path.join(titledir, 'extracted.' + ver)
	# Start with a clean dir
	if (os.path.exists(rootdir)):
		shutil.rmtree(rootdir)
	# Start with the root dir at index 0
	extractFstDirectory(titledir, fst, tmd, ckey, dkey, rootdir, 0)

def main():

	filedir = os.getcwd()						#Get Current Working Directory  Establishes this as the root directory
	titleid,c,ver =  getArgs()					#Parse CMDLINE Args and get results.  Currently c is deprecated 
	keys = []
	hex_keys = []

	ckey = open(os.path.join(filedir, 'ckey.bin'), 'rb').read(16)

	titledir = os.path.join(filedir, titleid)
	os.makedirs(titledir, exist_ok = True)

	ver = downloadTMD(titledir, titleid, ver)			# Download the tmd and cetk files
	tmd = parseTMD(titledir, ver)
	keys,hex_keys = loadTitleKeys(titledir, ver, ckey)		#keys: encryptedTitle, common, title_iv
	d_title_key, d_title_key_hex = decryptTitleKey(keys)
	print("Decrypted Title Key:", d_title_key_hex.upper())

	downloadTitles(titledir, tmd)

	decryptContentFiles(titledir, tmd, ckey, d_title_key)
	verifyContentHashes(titledir, tmd)

	print("Reading Contents:")
	fst = loadContent(titledir, tmd, keys[1], d_title_key)
	print("Found " + str((len(fst.fe_entries))) + " files")

	print("Extracting Files...\n")
	extractFiles(titledir, ver, fst, tmd, keys[1], d_title_key)



if __name__ == "__main__":
	main()
