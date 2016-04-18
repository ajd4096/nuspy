#!/usr/bin/env python3

import sys, os, shutil, pytmd, struct, functools
import	argparse
import binascii
import	bs4
import	calendar
import	csv
import hashlib
import re
import requests
import sqlite3
import time
import urllib.request

# My modules
import	global_vars
import	wiiubrew

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

# Global class to hold our CLI global_vars.options, so we don't have to pass them around
global_vars.options = None
		

def downloadTMD(titledir, titleid, ver):
	cache_dir = os.path.join(titledir, 'cache')
	
	if global_vars.options.verbose:
		print("Downloading TMD for:",titleid)

	try:
		if ver == None:
			# No version specified
			if global_vars.options.tagaya:
				# Get the version from our DB
				conn = sqlite3.connect('tagaya.db')
				csr = conn.cursor()
				csr.execute('''SELECT IFNULL(MAX(title_version), 0) FROM title_info WHERE title_id = ?''', [titleid])
				data = csr.fetchone()[0]
				conn.close()
				if global_vars.options.verbose:
					print("No Version Selected, Found:", data)
				ver = "%d" % data
			else:
				# Grab the latest (versionless tmd file)
				# Note that this may not be the most recent
				url = nus + titleid + r'/tmd'
				file = os.path.join(cache_dir, 'tmd')
				if global_vars.options.verbose:
					print("Downloading: %s" % url)
				# See if we can open the URL before creating the directory
				conn = urllib.request.urlopen(url)
				if conn:
					os.makedirs(cache_dir, exist_ok = True)
					urllib.request.urlretrieve(url, file)
					# Set the file's timestamp to the URL's Last-Modified
					last_modified = conn.headers['Last-Modified']
					if last_modified:
						t = time.mktime(time.strptime(last_modified, '%a, %d %b %Y %H:%M:%S %Z'))
						os.utime(file, (t,t))

					data = open(file, 'rb').read()
					tmdver = str((data[0x1DC] << 8) + data[0x1DD])						#TMD ver is at offset 0x1DC and is two bytes in length.  So we pack them together
					if global_vars.options.verbose:
						print("No Version Selected, Found:",tmdver)
					ver = tmdver

		if ver != None:
			url = nus + titleid + r'/tmd.'+ver
			file = os.path.join(cache_dir, 'tmd.' + ver)
			if os.path.isfile(file):
				if global_vars.options.verbose:
					print("Cached: %s" % file)
			else:
				if global_vars.options.verbose:
					print("Downloading: %s" % url)
				# See if we can open the URL before creating the directory
				conn = urllib.request.urlopen(url)
				if conn:
					os.makedirs(cache_dir, exist_ok = True)
					urllib.request.urlretrieve(url, file)
					# Set the file's timestamp to the URL's Last-Modified
					last_modified = conn.headers['Last-Modified']
					if last_modified:
						t = time.mktime(time.strptime(last_modified, '%a, %d %b %Y %H:%M:%S %Z'))
						os.utime(file, (t,t))

		return ver

	except Exception as e:
		print("Exception:",e)
		exit(1)

def downloadCETK(titledir, titleid):
	cache_dir = os.path.join(titledir, 'cache')

	print("Downloading CETK for:",titleid)

	try:
		url = nus + titleid + r'/cetk'
		file = os.path.join(cache_dir, 'cetk')
		if os.path.isfile(file):
			if global_vars.options.verbose:
				print("Cached: %s" % file)
		else:
			print("Downloading: %s" % url)
			# See if we can open the URL before creating the directory
			conn = urllib.request.urlopen(url)
			if conn:
				os.makedirs(cache_dir, exist_ok = True)
				urllib.request.urlretrieve(url, file)
				# Set the file's timestamp to the URL's Last-Modified
				last_modified = conn.headers['Last-Modified']
				if last_modified:
					t = time.mktime(time.strptime(last_modified, '%a, %d %b %Y %H:%M:%S %Z'))
					os.utime(file, (t,t))

	except Exception as e:
		print("Exception:",e)
		exit(1)

def	parseTMD(titledir, ver):
	cache_dir = os.path.join(titledir, 'cache')
	tmd_path = os.path.join(cache_dir, 'tmd.' +ver)
	if not os.path.isfile(tmd_path):
		print("TMD File Not Found!")
		exit(1)

	tmd = pytmd.TMD_PARSER()
	tmd.loadFile(tmd_path)
	print("Parsing TMD for: %s" % tmd.title_id_hex)
	print("Title version", tmd.tmd_title_version)
	if global_vars.options.verbose:
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
	if (expected_size and os.path.isfile(filename) and os.path.getsize(filename) >= expected_size):
		if global_vars.options.verbose:
			print("Cached:    ", url)
		return
	if expected_size:
		prefix = "\rDownloading: %s (%s) " % (url, humansize(expected_size))
	else:
		prefix = "\rDownloading: %s " % url
	req = urllib.request.Request(url)
	if os.path.isfile(filename):
		file_size = os.path.getsize(filename)
		req.headers['Range'] = 'bytes=%s-' % file_size
	else:
		file_size = 0
	sys.stdout.write("%s ..." % prefix)
	sys.stdout.flush()
	u = urllib.request.urlopen(req)
	if u:
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
			rate = len(data) / (end - start)
			if expected_size:
				percent = 100 * file_size // expected_size
				sys.stdout.write("%s %2d%%  %8.8s   " % (prefix, percent, humanrate(rate)))
			else:
				sys.stdout.write("%s %8.8s   " % (prefix, humanrate(rate)))
			sys.stdout.flush()
		f.close()
		# Set the file's atime, mtime
		last_modified = u.headers['Last-Modified']
		if last_modified:
			t = time.mktime(time.strptime(last_modified, '%a, %d %b %Y %H:%M:%S %Z'))
			os.utime(filename, (t,t))
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
	downloadFileProgress(url, filename, content.size)

	# Fetch the .h3 files
	if (content.type & 0x02):
		url += '.h3'
		filename += '.h3'
		# This should be 20 bytes for each 256MB (or part thereof)
		expected_size = 20 * ((content.size + 0x10000000 -1) // 0x10000000)
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
			if global_vars.options.verbose:
				print("Cached:     %s.plain" % filename)
		else:
			if global_vars.options.verbose:
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
			if global_vars.options.verbose:
				print("Cached:     %s.plain" % filename)
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
				if global_vars.options.verbose:
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

			if global_vars.options.verbose:
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
	
def	loadContent(titledir, ver, tmd, ckey, dkey):
	cache_dir = os.path.join(titledir, 'cache')

	decryptContentFile(titledir, tmd, ckey, dkey, tmd.tmd_contents[0])

	filename = os.path.join(cache_dir, tmd.tmd_contents[0].id + '.plain')

	if not os.path.isfile(filename):
		print("Error: can not open decrypted file %s" % filename)
		return

	data = open(filename, 'rb').read()

	unpacker = pytmd.buffer_unpacker(data)

	magic = unpacker.peek('>I')[0]

	# b'FST\0'
	if magic == 0x46535400:
		print("Reading Contents:")
		fst = pytmd.FST_PARSER()
		fst.unpack(unpacker)
		print("Found " + str((len(fst.fe_entries))) + " files")
		extractFiles(titledir, ver, fst, tmd, ckey, dkey)

	elif magic == 0xEFA282D9:
		hdr = pytmd.ANCAST_HEADER()
		hdr.unpack(unpacker)
		#print(type(hdr), hdr)
		extractAncastImage(titledir, ver, tmd, hdr)

def	extractFstDirectory(titledir, fst, tmd, ckey, dkey, currentdir, fstindex):
	cache_dir = os.path.join(titledir, 'cache')
	output_dir = os.path.join(titledir, 'extracted.' + tmd.tmd_title_version, currentdir)
	fe = fst.fe_entries[fstindex]

	if not global_vars.options.extract_meta_file and not global_vars.options.extract_meta_dir:
		if global_vars.options.verbose:
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
	cache_dir = os.path.join(titledir, 'cache')
	output_dir = os.path.join(titledir, 'extracted.' + tmd.tmd_title_version, currentdir)
	fe = fst.fe_entries[fstindex]
	output_file = os.path.join(output_dir, fe.fn)

	if not global_vars.options.original:
		if global_vars.options.list_content:
			print("Copying:   ", os.path.join(currentdir, fe.fn))
			return
		return

	original_dir = os.path.join(global_vars.options.original, currentdir)
	original_file = os.path.join(original_dir, fe.fn)

	if (global_vars.options.extract_meta_file and (currentdir != 'meta' or fe.fn != 'meta.xml')):
		return

	if (global_vars.options.extract_meta_dir and not (currentdir == 'meta') and not (currentdir == 'code' and (fe.fn == 'app.xml' or fe.fn == 'cos.xml'))):
		return

	if global_vars.options.list_content:
		print("Copying:   ", original_file)
		return

	if global_vars.options.verbose:
		print("Copying:   ", original_file)

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

	if (global_vars.options.extract_meta_file and (currentdir != 'meta' or fe.fn != 'meta.xml')):
		return

	if (global_vars.options.extract_meta_dir and not (currentdir == 'meta') and not (currentdir == 'code' and (fe.fn == 'app.xml' or fe.fn == 'cos.xml'))):
		return

	filename = os.path.join(output_dir, fe.fn)

	if global_vars.options.list_content:
		print("Extracting: %s (%d)" % (filename, fe.f_len))
		return

	if global_vars.options.verbose:
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
	if len(fst.fe_entries) == 0:
		print(type(fst), fst)
	extractFstDirectory(titledir, fst, tmd, ckey, dkey, '', 0)

def	extractAncastImage(titledir, ver, tmd, header):
	output_dir = os.path.join(titledir, 'extracted.' + tmd.tmd_title_version)

	# Start with a clean dir
	if (os.path.exists(output_dir)):
		shutil.rmtree(output_dir)
	if not os.path.isdir(output_dir):
		os.makedirs(output_dir)

	print("Extracting files into %s" % output_dir)

	# Check the hash
	if header.hash_type == 2:
		found = hashlib.sha1(header.body).digest()
		expected = header.body_hash
		if (found != expected):
			print("Hash mismatch")
			print("Expected %s" % binascii.hexlify(expected))
			print("Found    %s" % binascii.hexlify(found))
			exit(1)

	# Build our filename
	filename = os.path.join(output_dir, "image")
	if header.signature_type == 1:
		filename += '.ppc'
	elif header.signature_type == 2:
		filename += '.arm'

	# Decrypt the data
	decrypted_data = decryptData((header.body, binascii.unhexlify(header.key), binascii.unhexlify(header.iv))).encode('latin-1')

	# Write out the raw data
	output_file = open(filename + '.raw', 'wb')
	output_file.write(header.body)
	output_file.close()

	# Write out the decrypted data
	output_file = open(filename, 'wb')
	output_file.write(decrypted_data)
	output_file.close()

def	packageForWUP(titledir, ver, tmd, cetk, keys):
	cache_dir = os.path.join(titledir, 'cache')
	packagedir = os.path.join(titledir, 'install.' + tmd.tmd_title_version)

	# Start with a clean dir
	if (os.path.isdir(packagedir)):
		shutil.rmtree(packagedir)
	os.makedirs(packagedir, exist_ok = True)

	print("Packaging files for WUP installer into %s" % packagedir)

	# Copy our tmd, cetk files
	if global_vars.options.verbose:
		print("Copying: title.tmd")
	shutil.copy2(os.path.join(cache_dir, 'tmd.' + ver), os.path.join(packagedir, 'title.tmd'))

	if global_vars.options.verbose:
		print("Copying: title.tik")
	shutil.copy2(os.path.join(cache_dir, 'cetk'),       os.path.join(packagedir, 'title.tik'))

	# Copy the certs from the tmd, cetk files
	if global_vars.options.verbose:
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

		if global_vars.options.verbose:
			print("Copying: %s" % filename)
		shutil.copy2(os.path.join(cache_dir, filename),       os.path.join(packagedir, filename + '.app'))
		# If the content has a .h3, copy that too
		if (content.type & 0x02):
			if global_vars.options.verbose:
				print("Copying: %s" % filename + '.h3')
			shutil.copy2(os.path.join(cache_dir, filename + '.h3'),       os.path.join(packagedir, filename + '.h3'))

def	update_db_tagaya():

	#conn = sqlite3.connect(':memory:')
	conn = sqlite3.connect('tagaya.db')

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

		if global_vars.options.verbose:
			print("Fetching %s" % url)
		html = requests.get(url, verify='nintendo_cert_bundle.pem')
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
			requests.packages.urllib3.disable_warnings()
			html = requests.get(url, verify=False)
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

def	update_db_titlekeys():

	#conn = sqlite3.connect(':memory:')
	conn = sqlite3.connect('titlekeys.db')

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


	url = "https://docs.google.com/spreadsheets/d/1l427nnapxKEUBA-aAtiwAq1Kw6lgRV-hqdocpKY6vQ0/export?format=csv"
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

def	get_ekey_from_titlekeys(titleid):
	# Get the version from our DB
	conn = sqlite3.connect('titlekeys.db')
	csr = conn.cursor()
	csr.execute('''SELECT key_nus FROM title_keys WHERE title_id = ?''', [titleid])
	data = csr.fetchone()
	conn.close()
	if data:
		return data[0]

def main():
	parser = argparse.ArgumentParser(
		prog='nuspy.py',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description='Download, extract, and decrypt NUS files',
		epilog=
"""
For the lazy:

Download and extract TITLEID ready for loadiine:
%(prog)s -e --ekey=KEY TITLEID

Download and package UPDATEID ready for WUP installer:
%(prog)s -w UPDATEID

""")
	parser.add_argument('-v',	'--verbose',	dest='verbose',			help='verbose output',					action='count',			default=0)
	parser.add_argument('-V',	'--version',	dest='version',			help='download VERSION or latest if not specified',	metavar='VERSION')
	parser.add_argument('-b',	'--basedir',	dest='basedir',			help='use DIR as base directory',			metavar='DIR')
	parser.add_argument('-d',	'--download',	dest='download',		help='download all files at once',			action='store_true',		default=False)
	parser.add_argument('-e',	'--extract',	dest='extract',			help='extract content files',				action='store_true',		default=False)
	parser.add_argument('-l',	'--list',	dest='list_content',		help='list content files',				action='store_true',		default=False)
	parser.add_argument('-m',	'--meta-file',	dest='extract_meta_file',	help='extract only the meta.xml file',			action='store_true',		default=False)
	parser.add_argument('-M',	'--meta-dir',	dest='extract_meta_dir',	help='extract only the meta/ directory',		action='store_true',		default=False)
	parser.add_argument('-w',	'--wup',	dest='wup',			help='pack for WUP installer',				action='store_true',		default=False)
	parser.add_argument('-t',	'--tagaya',	dest='tagaya',			help='update title DB from tagaya',			action='store_true',		default=False)
	parser.add_argument(		'--titlekeys',	dest='titlekeys',		help='update titlekeys DB from G docs',			action='store_true',		default=False)
	parser.add_argument(		'--wiiubrew',	dest='wiiubrew',		help='update wiiubrew DB',				action='store_true',		default=False)
	parser.add_argument(		'--ckey',	dest='common_key',		help='use HEXKEY as common key',			metavar='HEXKEY')
	parser.add_argument(		'--dkey',	dest='dec_title_key',		help='use decrypted HEXKEY to decrypt the files',	metavar='HEXKEY')
	parser.add_argument(		'--ekey',	dest='enc_title_key',		help='use encrypted HEXKEY to decrypt the files',	metavar='HEXKEY')
	parser.add_argument(		'--original',	dest='original',		help='merge extracted content with original DIR',	metavar='DIR')
	parser.add_argument(		'titleid',	nargs=argparse.REMAINDER)
	global_vars.options = parser.parse_args()
	#print(type(global_vars.options), global_vars.options)

	filedir = global_vars.options.basedir
	if not filedir:
		filedir = os.getcwd()

	if global_vars.options.tagaya:
		update_db_tagaya()

	if global_vars.options.titlekeys:
		update_db_titlekeys()

	if global_vars.options.wiiubrew:
		wiiubrew.update_db_wiiubrew()

	if not len(global_vars.options.titleid):
		if not global_vars.options.tagaya and not global_vars.options.titlekeys and not global_vars.options.wiiubrew:
			parser.print_help()

	for titleid in global_vars.options.titleid:
		ver		= global_vars.options.version
		d_title_key	= None
		tmd		= None
		cetk		= None
		keys		= []

		# Make upper case, remove non-hex chars
		titleid = re.sub('[^0-9A-F]', '', titleid.upper())

		titledir = os.path.join(filedir, titleid)

		# Download and parse the TMD file(s)
		ver = downloadTMD(titledir, titleid, ver)			# Download the tmd and cetk files
		tmd = parseTMD(titledir, ver)

		if global_vars.options.common_key:
			ckey_hex = global_vars.options.common_key
		else:
			ckey_hex = b'D7B00402659BA2ABD2CB0DB27FA2B656'
		if global_vars.options.verbose:
			print("Using common key: %s" % ckey_hex)
		ckey = binascii.unhexlify(ckey_hex)

		if global_vars.options.dec_title_key:
			print("Using decrypted title key: %s" % global_vars.options.dec_title_key)
			d_title_key = binascii.unhexlify(global_vars.options.dec_title_key)

		elif global_vars.options.enc_title_key:
			print("Using encrypted title key: %s" % global_vars.options.enc_title_key)
			# Decrypt the encrypted title key using the common key and the title ID
			title_iv = tmd.title_id + b'\x00' * 8
			keys = ( binascii.unhexlify(global_vars.options.enc_title_key), ckey, title_iv)
			d_title_key = decryptTitleKey(keys)
		else:
			# Check our titlekeys DB
			ekey = get_ekey_from_titlekeys(titleid)
			if ekey:
				print("Using encrypted title key from DB: %s" % ekey)
				# Decrypt the encrypted title key using the common key and the title ID
				title_iv = tmd.title_id + b'\x00' * 8
				keys = ( binascii.unhexlify(ekey), ckey, title_iv)
				d_title_key = decryptTitleKey(keys)
			else:
				# Try without any key
				# Download and parse the CETK file
				downloadCETK(titledir, titleid)
				cetk = parseCETK(titledir)

				print("Using cetk key: %s" % binascii.hexlify(cetk.title_key))

				# Decrypt the encrypted title key using the common key and the title ID
				title_iv = tmd.title_id + b'\x00' * 8
				keys = (cetk.title_key, ckey, title_iv)
				d_title_key = decryptTitleKey(keys)

		print("Decrypted Title Key:", binascii.hexlify(d_title_key))

		if (global_vars.options.download):
			downloadTitles(titledir, tmd)

		if (global_vars.options.wup):
			if not cetk:
				print("Error: Packaging for WUP requires the cetk file")
				exit(1)
			packageForWUP(titledir, ver, tmd, cetk, keys)

		if (global_vars.options.extract or global_vars.options.extract_meta_file or global_vars.options.extract_meta_dir or global_vars.options.list_content):

			fst = loadContent(titledir, ver, tmd, ckey, d_title_key)


if __name__ == "__main__":
	main()
