#!/usr/bin/env python3

import sys, os, shutil, pytmd, struct, functools
import binascii
import hashlib
from optparse import OptionParser
import re
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

# Global class to hold our CLI options, so we don't have to pass them around
options = None
		

def downloadTMD(titledir, titleid, ver):
	cache_dir = os.path.join(titledir, 'cache')
	
	print("Downloading TMD for:",titleid)

	try:
		if ver == None:
			# No version specified, grab the latest (versionless tmd file)
			url = nus + titleid + r'/tmd'
			file = os.path.join(cache_dir, 'tmd')
			print("Downloading: %s" % url)
			# See if we can open the URL before creating the directory
			if urllib.request.urlopen(url):
				os.makedirs(cache_dir, exist_ok = True)
			urllib.request.urlretrieve(url, file)

			data = open(file, 'rb').read()
			tmdver = str((data[0x1DC] << 8) + data[0x1DD])						#TMD ver is at offset 0x1DC and is two bytes in length.  So we pack them together
			print("No Version Selected, Found:",tmdver)
			ver = tmdver

		if ver != None:
			url = nus + titleid + r'/tmd.'+ver
			file = os.path.join(cache_dir, 'tmd.' + ver)
			if os.path.isfile(file):
				if not options.quiet:
					print("Cached: %s" % file)
			else:
				print("Downloading: %s" % url)
				# See if we can open the URL before creating the directory
				if urllib.request.urlopen(url):
					os.makedirs(cache_dir, exist_ok = True)
				urllib.request.urlretrieve(url, file)

		return ver

	except Exception as e:
		print("Exception:",e)
		exit()

def downloadCETK(titledir, titleid):
	cache_dir = os.path.join(titledir, 'cache')

	print("Downloading CETK for:",titleid)

	try:
		url = nus + titleid + r'/cetk'
		file = os.path.join(cache_dir, 'cetk')
		if os.path.isfile(file):
			if not options.quiet:
				print("Cached: %s" % file)
		else:
			print("Downloading: %s" % url)
			# See if we can open the URL before creating the directory
			if urllib.request.urlopen(url):
				os.makedirs(cache_dir, exist_ok = True)
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
	print("Title version", tmd.tmd_title_version)
	if not options.quiet:
		print("Titles found:")
		for title in tmd.tmd_contents:
			print("ID:", title.id, "Index:", title.index, "Type:", title.type, "Size:", title.size)

	total_size = 0
	for title in tmd.tmd_contents:
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
	print("Downloading content files")
	for content in tmd.tmd_contents:
		downloadContentFile(titledir, tmd, content)

def	downloadContentFile(titledir, tmd, content):
	cache_dir = os.path.join(titledir, 'cache')
	url = nus + tmd.title_id_hex + r'/' + content.id
	filename = os.path.join(cache_dir, content.id)
	# If we don't have the file or it is too small, download it
	# FIXME: there are some titles where the file is larger than the tmd content.size.
	# For example: 0005000e1010fc00/00000001 is 32784 bytes, but content.size says 32769
	if (os.path.isfile(filename) and os.path.getsize(filename) >= content.size):
		if not options.quiet:
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
			if not options.quiet:
				print("Cached:", url)
		else:
			downloadFileProgress(url, filename, expected_size)

	return

#
# Decrypt 00000000 -> 00000000.plain
#
def	decryptContentFile(titledir, tmd, ckey, dkey, content):
	cache_dir = os.path.join(titledir, 'cache')
	filename = os.path.join(cache_dir, content.id)

	downloadContentFile(titledir, tmd, content)

	if not content.type & 0x02:
		if (os.path.isfile(filename + '.plain') and os.path.getsize(filename + '.plain') >= content.size):
			if not options.quiet:
				print("Cached: %s.plain" % filename)
		else:
			if not options.quiet:
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
			if not options.quiet:
				print("Cached: %s.plain" % filename)
		else:
			prefix = "\rDecrypting: %s" % filename

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

			block_count = content.size // 0x10000
			block_index = 0
			while True:
				if not options.quiet:
					block_percent = block_index * 100 // block_count
					sys.stdout.write("%s %2d%%" % (prefix, block_percent))
					sys.stdout.flush()

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

			if not options.quiet:
				sys.stdout.write("%s done\n" % prefix)
				sys.stdout.flush()

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
	
def	loadContent(titledir, tmd, ckey, dkey):
	cache_dir = os.path.join(titledir, 'cache')

	decryptContentFile(titledir, tmd, ckey, dkey, tmd.tmd_contents[0])

	filename = os.path.join(cache_dir, tmd.tmd_contents[0].id + '.plain')

	if not os.path.isfile(filename):
		print("Error: can not open decrypted file %s" % filename)
		return

	data = open(filename, 'rb').read()

	unpacker = pytmd.buffer_unpacker(data)

	fst = pytmd.FST_PARSER()
	fst.unpack(unpacker)
	#print(fst)
	
	return fst

def	extractFstDirectory(titledir, fst, tmd, ckey, dkey, currentdir, fstindex):
	cache_dir = os.path.join(titledir, 'cache')
	output_dir = os.path.join(titledir, 'extracted.' + tmd.tmd_title_version, currentdir)
	fe = fst.fe_entries[fstindex]

	if not options.extract_meta:
		if not options.quiet:
			print("Creating:  ", output_dir)
		if not os.path.isdir(output_dir):
			os.makedirs(output_dir)

	while (fstindex + 1 < fe.f_len):
		nextfe = fst.fe_entries[fstindex + 1]
		if (nextfe.type == 1 or nextfe.type == 129):
			fstindex = extractFstDirectory(titledir, fst, tmd, ckey, dkey, os.path.join(currentdir, nextfe.fn), fstindex + 1)
		elif (nextfe.type == 0):
			extractFstFile(titledir, fst, tmd, ckey, dkey, currentdir, fstindex + 1)
			fstindex += 1
		elif (nextfe.type == 0x80):
			extractFstFileCopy(titledir, fst, tmd, ckey, dkey, currentdir, fstindex + 1)
			fstindex += 1
		else:
			print("Unknown FST Entry type %d" % nextfe.type)
			fstindex += 1
	return fstindex

# If type == 0x80, the name/size matches existing files.
# The offset always seems to be 0
# I think this is a "copy from original" check
def	extractFstFileCopy(titledir, fst, tmd, ckey, dkey, currentdir, fstindex):
	if not options.original:
		return

	cache_dir = os.path.join(titledir, 'cache')
	original_dir = os.path.join(options.original, currentdir)
	output_dir = os.path.join(titledir, 'extracted.' + tmd.tmd_title_version, currentdir)
	fe = fst.fe_entries[fstindex]
	original_file = os.path.join(original_dir, fe.fn)
	output_file = os.path.join(output_dir, fe.fn)

	if (options.extract_meta and (not 'meta' in currentdir or not 'meta.xml' in fe.fn)):
		return

	if not options.quiet or options.extract_meta:
		print("Copying:", original_file)

	if not os.path.isfile(original_file):
		print("Error: Original file not found %s" % original_file)
		#exit(1)
		return

	if os.path.getsize(original_file) != fe.f_len:
		print("Warning: Original file size differs %s" % original_file)
		print("Expected: %s" % fe.f_len)
		print("Found: %s" % os.path.getsize(original_file))

	if not os.path.isdir(output_dir):
		os.makedirs(output_dir)
	shutil.copy(original_file, output_file)

def	extractFstFile(titledir, fst, tmd, ckey, dkey, currentdir, fstindex):
	cache_dir = os.path.join(titledir, 'cache')
	output_dir = os.path.join(titledir, 'extracted.' + tmd.tmd_title_version, currentdir)
	fe = fst.fe_entries[fstindex]

	if (options.extract_meta and (not 'meta' in currentdir or not 'meta.xml' in fe.fn)):
		return

	filename = os.path.join(output_dir, fe.fn)
	if not options.quiet or options.extract_meta:
		print("Extracting:", filename)

	# Find the correct content file
	for content in tmd.tmd_contents:
		if content.index == fe.content_id:
			break
	else:
		print("Error: Invalid content id %d" % fe.content_id)
		exit(1)

	decryptContentFile(titledir, tmd, ckey, dkey, content)
	input_filename = os.path.join(cache_dir, content.id + '.plain')
	if (not os.path.isfile(input_filename)):
		print('Error: Decrypted file missing %s' % input_filename)
		exit(1)

	# If flags = 0x400, offset is *0x20, length is ok
	# This matches the Yaz0 starts in 0005000E1018DD00/0000001e.plain
	offset = fe.f_off
	size = fe.f_len
	if fe.type == 0 and fe.flags == 0x400:
		offset *= 0x20

	# Check the size of the decrypted file
	if offset + size > os.path.getsize(input_filename):
		print('Error: Decrypted file too small %s' % input_filename)
		print("File:", os.path.getsize(input_filename))
		print(fe)
		exit(1)

	input_file = open(input_filename, 'rb')
	input_file.seek(offset)

	if not os.path.isdir(output_dir):
		os.makedirs(output_dir)
	output_file = open(filename, 'wb')

	# Copy the data in chunks (some files are big compared to memory size)
	chunk_size = 1024 * 1024
	while size > 0:
		if (size < chunk_size):
			data = input_file.read(size)
		else:
			data = input_file.read(chunk_size)
		if (len(data) == 0):
			print("Error: unable to read %d bytes" % size)
			exit(1)
		output_file.write(data)
		size -= len(data)
	output_file.close()
	input_file.close()

def	extractFiles(titledir, ver, fst, tmd, ckey, dkey):
	output_dir = os.path.join(titledir, 'extracted.' + tmd.tmd_title_version)

	# Start with a clean dir
	if (os.path.exists(output_dir)):
		shutil.rmtree(output_dir)

	print("Extracting files into %s" % output_dir)

	# Start with the root dir at index 0
	extractFstDirectory(titledir, fst, tmd, ckey, dkey, '', 0)

def	packageForWUP(titledir, ver, tmd, cetk, keys):
	cache_dir = os.path.join(titledir, 'cache')
	packagedir = os.path.join(titledir, 'install.' + tmd.tmd_title_version)

	# Start with a clean dir
	if (os.path.isdir(packagedir)):
		shutil.rmtree(packagedir)
	os.makedirs(packagedir, exist_ok = True)

	print("Packaging files for WUP installer into %s" % packagedir)

	# Copy our tmd, cetk files
	if not options.quiet:
		print("Copying: title.tmd")
	shutil.copy(os.path.join(cache_dir, 'tmd.' + ver), os.path.join(packagedir, 'title.tmd'))

	if not options.quiet:
		print("Copying: title.tik")
	shutil.copy(os.path.join(cache_dir, 'cetk'),       os.path.join(packagedir, 'title.tik'))

	# Copy the certs from the tmd, cetk files
	if not options.quiet:
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

		downloadContentFile(titledir, tmd, content)

		filename = content.id

		if not options.quiet:
			print("Copying: %s" % filename)
		shutil.copy(os.path.join(cache_dir, filename),       os.path.join(packagedir, filename + '.app'))
		# If the content has a .h3, copy that too
		if (content.type & 0x02):
			if not options.quiet:
				print("Copying: %s" % filename + '.h3')
			shutil.copy(os.path.join(cache_dir, filename + '.h3'),       os.path.join(packagedir, filename + '.h3'))

def main():
	# Make our CLI options global so we don't have to pass them around.
	global options

	parser = OptionParser(usage='usage: %prog [options] titleid1 titleid2')
	parser.add_option('-v',	'--version',	dest='version',		help='download VERSION or latest if not specified',		metavar='VERSION')
	parser.add_option('-q',	'--quiet',	dest='quiet',		help='quiet output',			action='store_true',		default=False)
	parser.add_option('-e',	'--extract',	dest='extract',		help='extract content',			action='store_true',		default=False)
	parser.add_option('-w',	'--wup',	dest='wup',		help='pack for WUP installer',		action='store_true',		default=False)
	parser.add_option('-d',	'--download',	dest='download',	help='download all files at once',	action='store_true',		default=False)
	parser.add_option('-m',	'--meta',	dest='extract_meta',	help='extract only the meta/meta.xml',	action='store_true',		default=False)
	parser.add_option('--ckey',	dest='common_key',	help='use HEXKEY as common key',		metavar='HEXKEY')
	parser.add_option('--dkey',	dest='dec_title_key',	help='use decrypted TITLEKEY to decrypt the files',		metavar='TITLEKEY')
	parser.add_option('--ekey',	dest='enc_title_key',	help='use encrypted TITLEKEY to decrypt the files',		metavar='TITLEKEY')
	parser.add_option('--original',	dest='original',	help='merge extracted content with original DIR',		metavar='DIR')
	(options, args) = parser.parse_args()

	filedir = os.getcwd()						#Get Current Working Directory  Establishes this as the root directory

	for titleid in args:
		ver		= options.version
		d_title_key	= None
		tmd		= None
		cetk		= None
		keys		= []

		# Make upper case, remove non-hex chars
		titleid = re.sub('[^0-9A-F]', '', titleid.upper())

		titledir = os.path.join(filedir, titleid)
		os.makedirs(titledir, exist_ok = True)

		# Download and parse the TMD file(s)
		ver = downloadTMD(titledir, titleid, ver)			# Download the tmd and cetk files
		tmd = parseTMD(titledir, ver)

		if options.common_key:
			ckey_hex = options.common_key
		else:
			ckey_hex = b'D7B00402659BA2ABD2CB0DB27FA2B656'
		if not options.quiet:
			print("Using common key: %s" % options.common_key)
		ckey = binascii.unhexlify(ckey_hex)

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

		if (options.download):
			downloadTitles(titledir, tmd)

		if (options.wup):
			if not cetk:
				print("Error: Packaging for WUP requires the cetk file")
				exit(1)
			packageForWUP(titledir, ver, tmd, cetk, keys)

		if (options.extract or options.extract_meta):

			print("Reading Contents:")
			fst = loadContent(titledir, tmd, ckey, d_title_key)
			print("Found " + str((len(fst.fe_entries))) + " files")

			extractFiles(titledir, ver, fst, tmd, ckey, d_title_key)


if __name__ == "__main__":
	main()
