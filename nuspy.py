#!/usr/bin/env python3

import sys, os, shutil, pytmd, struct, functools
import binascii
import hashlib
from optparse import OptionParser
import time
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


credits = """
	Data is no longer pulled from Wii U Impersonator! Yay!
	Data is now directly downloaded and parsed from the TMD ticket
	Thanks to fail0verfl0w for their efforts! Still thanks to them!
	Thanks WulfySytlez, Bug_Checker_, NWPlayer123. 
	Especially to Crediar for the CDecrypt source that was easy to 
	read, informative and documented well enough!
	Coded by Onion_Knight
	"""

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
		if ver == None:
			# No version specified, grab the latest (versionless tmd file)
			url = nus + titleid + r'/tmd'
			file = os.path.join(cache_dir, 'tmd')
			print("Downloading: %s" % url)
			urllib.request.urlretrieve(url, file)

			data = open(file, 'rb').read()
			tmdver = str((data[0x1DC] << 8) + data[0x1DD])						#TMD ver is at offset 0x1DC and is two bytes in length.  So we pack them together
			print("No Version Selected, Found:",tmdver)
			ver = tmdver

		if ver != None:
			url = nus + titleid + r'/tmd.'+ver
			file = os.path.join(cache_dir, 'tmd.' + ver)
			if os.path.isfile(file):
				print("Cached: %s" % file)
			else:
				print("Downloading: %s" % url)
				urllib.request.urlretrieve(url, file)

		return ver

	except Exception as e:
		print("Exception:",e)
		exit()

def downloadCETK(titledir, titleid):
	cache_dir = os.path.join(titledir, 'cache')
	os.makedirs(cache_dir, exist_ok = True)

	print("Downloading CETK for:",titleid)

	try:
		url = nus + titleid + r'/cetk'
		file = os.path.join(cache_dir, 'cetk')
		if os.path.isfile(file):
			print("Cached: %s" % file)
		else:
			print("Downloading: %s" % url)
			urllib.request.urlretrieve(url, file)

	except Exception as e:
		print("Exception:",e)
		exit()

def	parseTMD(titledir, ver):
	cache_dir = os.path.join(titledir, 'cache')
	tmd_path = os.path.join(cache_dir, 'tmd.' +ver)
	if not os.path.isfile(tmd_path):
		print("TMD File Not Found!")
		exit()

	tmd = pytmd.TMD_PARSER(tmd_path)
	tmd.ReadContent()
	print("Parsing TMD for: %s" % tmd.title_id_hex)
	print("Titles found:")
	total_size = 0
	for title in tmd.tmd_contents:
		print("ID:", title.id, "Index:", title.index, "Type:", title.type, "Size:", title.size)
		total_size += title.size
	print("Total size: %s" % humansize(total_size))

	return tmd

def	parseCETK(titledir):
	cache_dir = os.path.join(titledir, 'cache')

	cetk = pytmd.CETK()
	cetk.loadFile(os.path.join(cache_dir, 'cetk'))

	return cetk

def	humansize(nbytes):
	suffixes = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
	if nbytes == 0:
		return '0 B'
	i = 0
	while nbytes >= 1024 and i < len(suffixes)-1:
		nbytes /= 1024.
		i += 1
	f = ('%.1f' % nbytes).rstrip('0').rstrip('.')
	return '%s %s' % (f, suffixes[i])

def	humanrate(rate):
	suffixes = ['B/s', 'kB/s', 'MB/s', 'GB/s', 'TB/s', 'PB/s']
	if rate == 0:
		return '0 B/s'
	i = 0
	while rate >= 1000 and i < len(suffixes)-1:
		rate /= 1000.
		i += 1
	return '%3d %s' % (int((rate + 0.5)), suffixes[i])

#
# Download URL to FILE, and show progress in %
#
def	downloadFileProgress(url, filename, expected_size):
	prefix = "\rDownloading: %s (%s) " % (url, humansize(expected_size))
	req = urllib.request.Request(url)
	if os.path.isfile(filename):
		file_size = os.path.getsize(filename)
		req.headers['Range'] = 'bytes=%s-' % file_size
	else:
		file_size = 0
	sys.stdout.write("%s ..." % prefix)
	sys.stdout.flush()
	u = urllib.request.urlopen(req)
	f = open(filename, 'ab')
	while True:
		start = time.time()
		data = u.read(1024*1024)
		if not data:
			break
		f.write(data)
		f.flush()
		end = time.time()
		file_size += len(data)
		percent = 100 * file_size // expected_size
		rate = len(data) / (end - start)
		sys.stdout.write("%s %2d%%  %8.8s" % (prefix, percent, humanrate(rate)))
		sys.stdout.flush()
	f.close()
	sys.stdout.write("%s done\n" % prefix)
	sys.stdout.flush()


def downloadTitles(titledir, tmd):
	cache_dir = os.path.join(titledir, 'cache')
	print("Downloading content files")
	for content in tmd.tmd_contents:
		url = nus + tmd.title_id_hex + r'/' + content.id
		filename = os.path.join(cache_dir, content.id)
		# If we don't have the file or it is too small, download it
		# FIXME: there are some titles where the file is larger than the tmd content.size.
		# For example: 0005000e1010fc00/00000001 is 32784 bytes, but content.size says 32769
		if (os.path.isfile(filename) and os.path.getsize(filename) >= content.size):
			print("Cached:", url)
		else:
			downloadFileProgress(url, filename, content.size)

		# Fetch the .h3 files
		if (content.type & 0x02):
			url += '.h3'
			filename += '.h3'
			# This should be 20 bytes for each 256MB (or part thereof)
			expected_size = 20 * ((content.size + 0x10000000 -1) // 0x10000000)
			if (os.path.isfile(filename) and os.path.getsize(filename) >= expected_size):
				print("Cached:", url)
			else:
				downloadFileProgress(url, filename, expected_size)

	return

#
# Decrypt 00000000 -> 00000000.plain
#
def decryptContentFiles(titledir, tmd, ckey, dkey):
	cache_dir = os.path.join(titledir, 'cache')
	print("Decrypting content files")
	for content in tmd.tmd_contents:
		filename = os.path.join(cache_dir, content.id)


		if not content.type & 0x02:
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

				# Check our SHA1 hash
				# Only checksum the content.size
				found = hashlib.sha1(decrypted_data[:content.size]).digest()
				expected = content.sha1_hash[:20]
				if (found != expected):
					print("Hash mismatch")
					print("Expected %s" % binascii.hexlify(expected))
					print("Found    %s" % binascii.hexlify(found))
					exit(1)
				else:
					#print("Hash ok")
					pass

				# Write the decrypted file.plain
				open(filename + ".plain", "wb").write(decrypted_data)
		else:
			if (os.path.isfile(filename + '.plain') and os.path.getsize(filename + '.plain') >= content.size * 0xFC00 // 0x10000):
				print("Cached: %s.plain" % filename)
			else:
				print("Decrypting: %s" % filename)

				# Process in input blocks of 0x10000, output blocks of 0xFC00
				# The first 0x400 bytes of each block contain the H0,H1,H2 hashes
				# H0 (0-15) are repeated 16x and indexed by (block_index % 16)
				# H1 (16-31) are repeated 256x and indexed by ((block_index / 16) % 16) ?
				# H2 (32-47) are repeated 4096x and indexed by ((block_index / 256) % 16) ?
				# H3 (0-N) are stored in the .h3 file and indexed by (block_index / 4096)
				# Each hash is a 20-byte SHA1

				# Read in our .h3 file
				H3_hashes = open(filename + '.h3', 'rb').read()

				# Check our SHA1 hash
				found = hashlib.sha1(H3_hashes).digest()
				expected = content.sha1_hash[:20]
				if (found != expected):
					print("Hash mismatch for .h3 file")
					print("Expected %s" % binascii.hexlify(expected))
					print("Found    %s" % binascii.hexlify(found))
					exit(1)
				else:
					#print("Hash ok for .h3 file")
					pass

				enc_file = open(filename, 'rb')
				dec_file = open(filename + ".plain", 'wb')

				block_index = 0
				while True:
					#print("Block %d" % block_index)

					# Read the encrypted file
					enc_data = enc_file.read(0x10000)
					if enc_data == '':
						break
					if len(enc_data) < 0x400:
						break

					# Set up our IV using the content index
					iv_key = bytearray(b'\x00' * 16)
					iv_key[1] = content.index

					# Decrypt the hash block
					dec_hashes = bytearray(decryptData((enc_data[: 0x400], dkey, iv_key)).encode('latin-1'))
					dec_hashes[1] ^= content.index

					# Get the starting point of each hash level
					H0_start = (block_index % 16) * 20
					H1_start = (16 + (block_index // 16) % 16) * 20
					H2_start = (32 + (block_index // 256) % 16) * 20
					H3_start = ((block_index // 4096) % 16) * 20

					# Set up our IV from the H0 hash
					iv_key = bytearray(dec_hashes[H0_start : H0_start + 16])

					# Decrypt the next 0xFC00 bytes
					dec_data = decryptData((enc_data[0x400 : ], dkey, iv_key)).encode('latin-1')

					# Check our H0 hash
					found = hashlib.sha1(dec_data).digest()
					expected = dec_hashes[H0_start : H0_start + 20]
					if (found != expected):
						print("Hash mismatch for H0 block %d" % block_index)
						print("Expected %s" % binascii.hexlify(expected))
						print("Found    %s" % binascii.hexlify(found))
						exit(1)
					else:
						#print("Hash ok for H0 block %d" % block_index)
						pass

					# Check our H1 hash
					if ((block_index % 16) == 0):
						found = hashlib.sha1(dec_hashes[H0_start : H0_start + 16 * 20]).digest()
						expected = dec_hashes[H1_start : H1_start + 20]
						if (found != expected):
							print("Hash mismatch for H1 block %d" % block_index)
							print("Expected %s" % binascii.hexlify(expected))
							print("Found    %s" % binascii.hexlify(found))
							exit(1)
						else:
							#print("Hash ok for H1 block %d" % block_index)
							pass

					# Check our H2 hash
					if ((block_index % 256) == 0):
						found = hashlib.sha1(dec_hashes[H1_start : H1_start + 16 * 20]).digest()
						expected = dec_hashes[H2_start : H2_start + 20]
						if (found != expected):
							print("Hash mismatch for H2 block %d" % block_index)
							print("Expected %s" % binascii.hexlify(expected))
							print("Found    %s" % binascii.hexlify(found))
							exit(1)
						else:
							#print("Hash ok for H2 block %d" % block_index)
							pass

					# Check our H3 hash
					if ((block_index % 4096) == 0):
						found = hashlib.sha1(dec_hashes[H2_start : H2_start + 16 * 20]).digest()
						expected = H3_hashes[H3_start : H3_start + 20]
						if (found != expected):
							print("Hash mismatch for H3 block %d" % block_index)
							print("Expected %s" % binascii.hexlify(expected))
							print("Found    %s" % binascii.hexlify(found))
							exit(1)
						else:
							#print("Hash ok for H3 block %d" % block_index)
							pass

					# Write out the decrypted data
					dec_file.write(dec_data)

					# Count our block #
					block_index += 1

				dec_file.close()
				enc_file.close()

# Wierd design choice, return decrypted data as a string
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

	# Convert our string back to an array of bytes
	dtkey  = bytes(decrypted.encode('latin-1'))

	return dtkey
	
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

	print("Extracting files into %s" % rootdir)

	# Start with the root dir at index 0
	extractFstDirectory(titledir, fst, tmd, ckey, dkey, rootdir, 0)

def	packageForWUP(titledir, ver, tmd, cetk, keys):
	cache_dir = os.path.join(titledir, 'cache')
	packagedir = os.path.join(titledir, 'install.' + ver)

	# Start with a clean dir
	if (os.path.isdir(packagedir)):
		shutil.rmtree(packagedir)
	os.makedirs(packagedir, exist_ok = True)

	print("Packaging files for WUP installer into %s" % packagedir)

	# Copy our tmd, cetk files
	print("Copying: title.tmd")
	shutil.copy(os.path.join(cache_dir, 'tmd.' + ver), os.path.join(packagedir, 'title.tmd'))

	print("Copying: title.tik")
	shutil.copy(os.path.join(cache_dir, 'cetk'),       os.path.join(packagedir, 'title.tik'))

	# Copy the certs from the tmd, cetk files
	print("Creating: title.cert")
	packer = pytmd.buffer_packer()

	# We can take our root cert from either file
	cetk.certificates[1].pack(packer)
	#tmd.certificates[1].pack(packer)

	tmd.certificates[0].pack(packer)

	cetk.certificates[0].pack(packer)

	open(os.path.join(packagedir, 'title.cert'), 'wb').write(bytes(packer._buffer))

	#f.write(c[0x650 : 0x650 + 0x400])
	#f.write(t[0x1224 : 0x1224 + 0x300])
	#f.write(c[0x350 : 0x350 + 0x300])

	# Copy the encrypted content files
	for content in tmd.tmd_contents:
		filename = content.id

		print("Copying: %s" % filename)
		shutil.copy(os.path.join(cache_dir, filename),       os.path.join(packagedir, filename + '.app'))
		# If the content has a .h3, copy that too
		if (content.type & 0x02):
			print("Copying: %s" % filename + '.h3')
			shutil.copy(os.path.join(cache_dir, filename + '.h3'),       os.path.join(packagedir, filename + '.h3'))

def main():

	parser = OptionParser(usage='usage: %prog [options] titleid1 titleid2')
	parser.add_option('-v',	'--version',	dest='version',		help='download VERSION or latest if not specified',		metavar='VERSION')
	parser.add_option('-e',	'--extract',	dest='extract',		help='extract content',			action='store_true',		default=False)
	parser.add_option('-w',	'--wup',	dest='wup',		help='pack for WUP installer',		action='store_true',		default=False)
	parser.add_option('--dkey',	dest='dec_title_key',	help='use decrypted TITLEKEY to decrypt the files',		metavar='TITLEKEY')
	parser.add_option('--ekey',	dest='enc_title_key',	help='use encrypted TITLEKEY to decrypt the files',		metavar='TITLEKEY')
	(options, args) = parser.parse_args()

	filedir = os.getcwd()						#Get Current Working Directory  Establishes this as the root directory

	for titleid in args:
		ver		= options.version
		d_title_key	= None
		tmd		= None
		cetk		= None
		keys		= []
		#hex_keys	= []

		ckey = open(os.path.join(filedir, 'ckey.bin'), 'rb').read(16)

		titledir = os.path.join(filedir, titleid)
		os.makedirs(titledir, exist_ok = True)

		# Download and parse the TMD file(s)
		ver = downloadTMD(titledir, titleid, ver)			# Download the tmd and cetk files
		tmd = parseTMD(titledir, ver)

		if options.dec_title_key:
			print("Using decrypted title key: %s" % options.dec_title_key)
			d_title_key = binascii.unhexlify(options.dec_title_key)

		elif options.enc_title_key:
			print("Using encrypted title key: %s" % options.enc_title_key)
			# Decrypt the encrypted title key using the common key and the title ID
			title_iv = tmd.title_id + b'\x00' * 8
			keys = ( binascii.unhexlify(options.enc_title_key), ckey, title_iv)
			d_title_key = decryptTitleKey(keys)

		else:
			# Download and parse the CETK file
			downloadCETK(titledir, titleid)
			cetk = parseCETK(titledir)

			print("Using cetk key: %s" % binascii.hexlify(cetk.title_key))

			# Decrypt the encrypted title key using the common key and the title ID
			title_iv = tmd.title_id + b'\x00' * 8
			keys = (cetk.title_key, ckey, title_iv)
			d_title_key = decryptTitleKey(keys)

		print("Decrypted Title Key:", binascii.hexlify(d_title_key))

		if (options.wup):
			if not cetk:
				print("Error: Packaging for WUP requires the cetk file")
				exit(1)
			downloadTitles(titledir, tmd)
			packageForWUP(titledir, ver, tmd, cetk, keys)

		if (options.extract):
			downloadTitles(titledir, tmd)
			decryptContentFiles(titledir, tmd, ckey, d_title_key)

			print("Reading Contents:")
			fst = loadContent(titledir, tmd, ckey, d_title_key)
			print("Found " + str((len(fst.fe_entries))) + " files")

			extractFiles(titledir, ver, fst, tmd, ckey, d_title_key)



if __name__ == "__main__":
	main()
