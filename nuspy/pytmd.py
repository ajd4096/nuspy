
import binascii
import collections
import ctypes
import functools
import hashlib
import struct

# My modules
import nuspy.global_vars as global_vars

WiiUCommenDevKey = b'\x2F\x5C\x1B\x29\x44\xE7\xFD\x6F\xC3\x97\x96\x4B\x05\x76\x91\xFA'
wiiu_common_key = b'\xD7\xB0\x04\x02\x65\x9B\xA2\xAB\xD2\xCB\x0D\xB2\x7F\xA2\xB6\x56'

# Set the -vvv level to output debugging info
DEBUG_LEVEL	= 3

def	get_signature_type(key, value):
	# Taken from http://www.3dbrew.org/wiki/Title_metadata
	signature_types = (
		{ 'name':	b'RSA_4096_SHA1',	'value': 0x00010000,	'size': 512,	'padding': 0x3C, },
		{ 'name':	b'RSA_2048_SHA1',	'value': 0x00010001,	'size': 256,	'padding': 0x3C, },
		{ 'name':	b'ECDSA_SHA1',		'value': 0x00010002,	'size': 60,	'padding': 0x40, },
		{ 'name':	b'RSA_4096_SHA256',	'value': 0x00010003,	'size': 512,	'padding': 0x3C, },
		{ 'name':	b'RSA_2048_SHA256',	'value': 0x00010004,	'size': 256,	'padding': 0x3C, },
		{ 'name':	b'ECDSA_SHA256',	'value': 0x00010005,	'size': 60,	'padding': 0x40, },
		{ 'name':	b'RSA_2048_SHA256?',	'value': 0x00020004,	'size': 256,	'padding': 0x3C, },	# found in WUD
		{ 'name':	b'RSA_2048_SHA256?',	'value': 0x00030004,	'size': 256,	'padding': 0x3C, },	# found in WUD
	)
	for t in signature_types:
		if t[key] == value:
			return t
	if (key == 'name'):
		print("%s %s" % (key, value))
	elif (key == 'value'):
		print("%s %d 0x%X" % (key, value, value))
	elif (key == 'size'):
		print("%s %d 0x%X" % (key, value, value))
	elif (key == 'padding'):
		print("%s %d 0x%X" % (key, value, value))
	else:
		print(key, value)
	assert False, "Unrecognised signature type"

class	buffer_packer():
	def __init__(self):
		self._buffer = []

	def __call__(self, fmt, data):
		self._buffer += struct.pack(fmt, data)

	def	tell(self):
		return len(self._buffer)

class	buffer_unpacker():
	def __init__(self, buffer):
		self._buffer = buffer
		self._offset = 0

	def __call__(self, fmt):
		if global_vars.options.verbose >= DEBUG_LEVEL:
			r = min(16, (self.length() - self.tell()))
			if r > 0:
				print("%d 0x%X" % (self._offset, self._offset), fmt, self._buffer[self._offset : self._offset + r])
		result = struct.unpack_from(fmt, self._buffer, self._offset)
		self._offset += struct.calcsize(fmt)
		return result

	def	iseof(self):
		if self._offset >= len(self._buffer):
			return True
		return False

	def	length(self):
		return len(self._buffer)

        # Get the next output without moving the offset
	def	peek(self, fmt):
		off = self.tell()
		out = self(fmt)
		self.seek(off)
		return out

	def	peek16(self):
		r = min(16, (self.length() - self.tell()))
		if r > 0:
			return self.peek('<%dB' % r)
		return "EOF"

	def	seek(self, offset):
		if offset >= 0 and offset < len(self._buffer):
			self._offset = offset
		return self._offset

	def	tell(self):
		return self._offset

class	SIGNATURE():
	def	__init__(self):
		# We hook __getattr__/__setattr__ so we can use "header.body" etc
		# To prevent recursion we need to set our _data member directly.
		self.__dict__['_data'] = collections.OrderedDict()

	def __getattr__(self, name):
		return self._data.get(name, None)

	def __setattr__(self, name, value):
		if global_vars.options.verbose >= DEBUG_LEVEL:
			print("%s.%s=%s" % (__class__.__name__, name, value))
		self._data[name] = value

	def	__str__(self):
		o = ''
		o += '{ sig\n'
		st = get_signature_type('value', self.sig_type)
		if st:
			o += "Sig Type: %s\n" % st['name']
			o += "Sig Size: 0x%X\n" % st['size']
		o += '} sig\n'
		return o

	def	get_length(self):
		st = get_signature_type('value', self.sig_type)
		if st:
			return st['size']

	def	get_padding(self):
		st = get_signature_type('value', self.sig_type)
		if st:
			return st['padding']

	def	pack(self, packer):
		packer('>I', self.sig_type)
		packer('>%ds' % self.get_length(), self.signature)
		packer('>%ds' % self.get_padding(), self.padding)

	def	unpack(self, unpacker):
		self.sig_type		= unpacker('>I')[0]
		self.signature		= unpacker('>%ds' % self.get_length())[0]
		self.padding		= unpacker('>%ds' % self.get_padding())[0]
		return self

class TMD_CONTENT():
	def	__init__(self):
		# We hook __getattr__/__setattr__ so we can use "header.body" etc
		# To prevent recursion we need to set our _data member directly.
		self.__dict__['_data'] = collections.OrderedDict()

	def __getattr__(self, name):
		return self._data.get(name, None)

	def __setattr__(self, name, value):
		if global_vars.options.verbose >= DEBUG_LEVEL:
			print("%s.%s=%s" % (__class__.__name__, name, value))
		self._data[name] = value

	def	pack(self, packer):
		packer('>I',	int.from_bytes(self.id, 16))
		packer('>H',	self.index)
		packer('>H',	self.type)
		packer('>Q',	self.size)
		packer('>32s',	self.sha1_hash)

	def	unpack(self, unpacker):
		self.id		= '%08X' % unpacker('>I')[0]
		self.index	= unpacker('>H')[0]
		self.type	= unpacker('>H')[0]
		self.size	= unpacker('>Q')[0]
		self.sha1_hash	= unpacker('>32s')[0]

class	TMD_CERT():
	def	__init__(self):
		# We hook __getattr__/__setattr__ so we can use "header.body" etc
		# To prevent recursion we need to set our _data member directly.
		self.__dict__['_data'] = collections.OrderedDict()

	def __getattr__(self, name):
		return self._data.get(name, None)

	def __setattr__(self, name, value):
		if global_vars.options.verbose >= DEBUG_LEVEL:
			print("%s.%s=%s" % (__class__.__name__, name, value))
		self._data[name] = value

	def	__str__(self):
		o = ''
		o += '{ cert\n'
		o += str(self.signature)
		o += "Name: %s\n" % self.name
		o += "Issuer: %s\n" % self.issuer
		o += "Tag: 0x%X\n" % self.tag
		o += '} cert\n'
		return o

	def	pack(self, packer):
		self.signature.pack(packer)
		packer('>64s',		self.issuer)
		packer('>I',		self.tag)
		packer('>64s',		self.name)
		packer('>316s',		self.key)

	def	unpack(self, unpacker):
		self.signature		= SIGNATURE().unpack(unpacker)
		self.issuer		= unpacker('>64s')[0].rstrip(b'\x00')
		self.tag		= unpacker('>I')[0]
		self.name		= unpacker('>64s')[0].rstrip(b'\x00')
		self.key		= unpacker('>316s')[0]

class	CETK():
	def	__init__(self):
		# We hook __getattr__/__setattr__ so we can use "header.body" etc
		# To prevent recursion we need to set our _data member directly.
		self.__dict__['_data'] = collections.OrderedDict()

	def __getattr__(self, name):
		return self._data.get(name, None)

	def __setattr__(self, name, value):
		if global_vars.options.verbose >= DEBUG_LEVEL:
			print("%s.%s=%s" % (__class__.__name__, name, value))
		self._data[name] = value

	def	__str__(self):
		o = ''
		o += '{ cetk\n'
		o += str(self.signature)
		o += "Issuer: %s\n" % self.issuer
		#self.public_key			= unpacker('>60s')[0]
		o += "Version %d\n" % self.version
		#self.ca_crl_version		= unpacker('B')[0]
		#self.signer_crl_version	= unpacker('B')[0]
		#self.title_key			= unpacker('>16s')[0]
		#self.reserved1			= unpacker('B')[0]
		#self.ticket_id			= unpacker('>Q')[0]
		#self.console_id			= unpacker('>I')[0]
		o += "Title ID %8X\n" % self.title_id
		#self.reserved2			= unpacker('>H')[0]
		#self.ticket_title_version	= unpacker('>H')[0]
		#self.reserved3			= unpacker('8s')[0]
		#self.license_type		= unpacker('B')[0]
		o += "CKEY index %X\n" % self.ckey_index
		#self.reserved4			= unpacker('42s')[0]
		#self.account_id		= unpacker('>I')[0]
		#self.reserved5			= unpacker('B')[0]
		#self.audit			= unpacker('B')[0]
		#self.reserved6			= unpacker('66s')[0]
		#self.limits			= unpacker('64s')[0]
		#self.content_index		= unpacker('172s')[0]
		#self.certificates = []
		for i in range(len(self.certificates)):
			o += str(self.certificates[i])
		o += '} cetk\n'

		return o

	def	loadFile(self, filename):
		#print(type(filename), filename)
		unpacker = buffer_unpacker(open(filename, 'rb').read())
		self.unpack(unpacker)

	def	unpack(self, unpacker):
		self.signature			= SIGNATURE().unpack(unpacker)
		self.issuer			= unpacker('>64s')[0].rstrip(b'\x00')
		self.public_key			= unpacker('>60s')[0]
		self.version			= unpacker('B')[0]
		self.ca_crl_version		= unpacker('B')[0]
		self.signer_crl_version		= unpacker('B')[0]
		self.title_key			= unpacker('>16s')[0]
		self.reserved1			= unpacker('B')[0]
		self.ticket_id			= unpacker('>Q')[0]
		self.console_id			= unpacker('>I')[0]
		self.title_id			= unpacker('>Q')[0]
		self.reserved2			= unpacker('>H')[0]
		self.ticket_title_version	= unpacker('>H')[0]
		self.reserved3			= unpacker('8s')[0]
		self.license_type		= unpacker('B')[0]
		self.ckey_index			= unpacker('B')[0]
		self.reserved4			= unpacker('42s')[0]
		self.account_id			= unpacker('>I')[0]
		self.reserved5			= unpacker('B')[0]
		self.audit			= unpacker('B')[0]
		self.reserved6			= unpacker('66s')[0]
		self.limits			= unpacker('64s')[0]
		self.content_index		= unpacker('H')[0]
		self.reserved7			= unpacker('5s')[0]
		self.cert_offset		= unpacker('B')[0]
		# More stuff in here, seems to be some sort of very long bit mask
		unpacker.seek(0x2A4 + self.cert_offset)
		certificates = []
		while not unpacker.iseof():
			cert = TMD_CERT()
			cert.unpack(unpacker)
			certificates.append(cert)
		self.certificates = certificates

class TMD_PARSER():
	""" Parses Wii U TMD """
	def	__init__(self):
		# We hook __getattr__/__setattr__ so we can use "header.body" etc
		# To prevent recursion we need to set our _data member directly.
		self.__dict__['_data'] = collections.OrderedDict()

	def __getattr__(self, name):
		return self._data.get(name, None)

	def __setattr__(self, name, value):
		if global_vars.options.verbose >= DEBUG_LEVEL:
			print("%s.%s=%s" % (__class__.__name__, name, value))
		self._data[name] = value

	def	loadFile(self, filename):
		#print(type(filename), filename)
		unpacker = buffer_unpacker(open(filename, 'rb').read())
		self.unpack(unpacker)

	def	unpack(self, unpacker):
		self.tmd_signature		= SIGNATURE().unpack(unpacker)

		self.tmd_issuer			= unpacker('>64s')[0]
		self.tmd_version		= unpacker('1c')[0]
		self.tmd_ca_crl_version		= unpacker('1c')[0]
		self.tmd_signer_crl_version	= unpacker('1c')[0]
		self.tmd_padding2		= unpacker('1c')[0]
		self.tmd_system_version		= '%016x' % unpacker('>Q')[0]
		# The title ID is an 8-byte hex number, but it is an ID, not an int
		# (We will not be using it to add/subtract/ etc)
		# Read it in as a string
		self.title_id			= unpacker('>8s')[0]
		self.title_id_hex		= binascii.hexlify(self.title_id).decode('latin-1').upper()
		self.tmd_title_type		= unpacker('>I')[0]
		self.tmd_group_id		= unpacker('>H')[0]
		self.tmd_public_save_size	= unpacker('>I')[0]
		self.tmd_private_save_size	= unpacker('>I')[0]
		self.tmd_reserved1		= unpacker('>I')[0]
		self.tmd_srl_flag		= unpacker('1c')[0]
		self.tmd_reserved2		= unpacker('49s')[0]
		self.tmd_access_rights		= '%08X' % unpacker('>I')[0]
		self.tmd_title_version		= unpacker('>H')[0]
		self.tmd_number_of_contents	= unpacker('>H')[0]
		self.tmd_boot_index		= unpacker('>H')[0]
		self.tmd_padding3		= unpacker('2s')[0]
		self.tmd_hash_table_hash	= unpacker('>32s')[0]

		# Validate the CIR table hash
		offset = unpacker.tell()
		cir_table_hash = hashlib.sha256(unpacker._buffer[offset : offset + 0x24 * 64]).digest()
		if (self.tmd_hash_table_hash != cir_table_hash):
			print("Hash mismatch for CIR table")
			print("Expected: %s" % self.tmd_hash_table_hash)
			print("Found: %s" % cir_table_hash)
		else:
			#print("Hash ok for CIR table")
			pass

		# Read in all the content info records
		tmd_content_info_records = []
		for i in range(64):
			(cir_offset, cir_count, cir_hash)	= unpacker('>HH32s')
			tmd_content_info_records.append((cir_offset, cir_count, cir_hash))
		self.tmd_content_info_records = tmd_content_info_records

		# Validate the CIR entry hashes
		# (Guessed starting offset, only ever seen the 1st CIR used to hash all the CCR)
		offset = unpacker.tell()
		for i in range(64):
			(cir_offset, cir_count, cir_hash) = self.tmd_content_info_records[i]
			if cir_count:
				start = offset + cir_offset * 0x30
				ccr_hash = hashlib.sha256(unpacker._buffer[start : start + cir_count * 0x30]).digest()
				if ccr_hash != cir_hash:
					print("Hash mismatch for CIR entry %d" %  i)
					print("Expected: %s" % cir_hash)
					print("Found: %s" % ccr_hash)
				else:
					#print("Hash ok for CIR entry %d" %  i)
					pass

		# Read in the content records
		tmd_contents = []
		for content in range(0, self.tmd_number_of_contents):
			tmd_cnt = TMD_CONTENT()
			tmd_cnt.unpack(unpacker)
			tmd_contents.append(tmd_cnt)
		self.tmd_contents = tmd_contents

		# Read in any certificates after
		certificates = []
		while not unpacker.iseof():
			#print("Found cert at 0x%X" % unpacker.tell())
			cert = TMD_CERT()
			cert.unpack(unpacker)
			certificates.append(cert)
		self.certificates = certificates



class FST_CONTENT():
	def	__init__(self):
		# We hook __getattr__/__setattr__ so we can use "header.body" etc
		# To prevent recursion we need to set our _data member directly.
		self.__dict__['_data'] = collections.OrderedDict()

	def __getattr__(self, name):
		return self._data.get(name, None)

	def __setattr__(self, name, value):
		if global_vars.options.verbose >= DEBUG_LEVEL:
			print("%s.%s=%s" % (__class__.__name__, name, value))
		self._data[name] = value

	def	__str__(self):
		o = ""
		o += "%X " % self.unk
		o += "%d " % self.size
		o += "%X " % self.unk2
		for x in self.unklist:
			o += "%X " % x
		o += "\n"
		return o

	def	unpack(self, unpacker):
		self.unk		= unpacker('>I')[0]
		self.size		= unpacker('>I')[0]
		self.unk2		= unpacker('>I')[0]
		self.unklist		= unpacker('>5I')


class FE_ENTRY():
	def	__init__(self):
		# We hook __getattr__/__setattr__ so we can use "header.body" etc
		# To prevent recursion we need to set our _data member directly.
		self.__dict__['_data'] = collections.OrderedDict()

	def __getattr__(self, name):
		return self._data.get(name, None)

	def __setattr__(self, name, value):
		if global_vars.options.verbose >= DEBUG_LEVEL:
			print("%s.%s=%s" % (__class__.__name__, name, value))
		self._data[name] = value

	def	__str__(self):
		o = ""
		o += "type: %X\n" % self.type
		o += "name_offset: %d\n" % self.name_offset
		o += "f_off: %d\n" % self.f_off
		o += "f_len: %d\n" % self.f_len
		o += "parent: %s\n" % self.parent
		o += "next: %s\n" % self.next
		o += "flags: %X\n" % self.flags
		o += "content_id: %d\n" % self.content_id
		o += "fn: %s\n" % self.fn
		return o

	def	unpack(self, unpacker):
		TypeName		= unpacker('>I')[0]
		self.type		= TypeName >> 24
		self.name_offset	= TypeName & 0x00FFFFFF
		self.f_off		= unpacker('>I')[0]
		self.f_len		= unpacker('>I')[0]
		self.flags		= unpacker('>H')[0]
		self.content_id		= unpacker('>H')[0]
		self.fn			= ''

class FST_PARSER():
	def	__init__(self):
		# We hook __getattr__/__setattr__ so we can use "header.body" etc
		# To prevent recursion we need to set our _data member directly.
		self.__dict__['_data'] = collections.OrderedDict()

	def __getattr__(self, name):
		return self._data.get(name, None)

	def __setattr__(self, name, value):
		if global_vars.options.verbose >= DEBUG_LEVEL:
			print("%s.%s=%s" % (__class__.__name__, name, value))
		self._data[name] = value

	def	__str__(self):
		o = ""
		o += "Magic: %X\n" % self.magic
		o += "?: %X\n" % self.unknown1
		o += "ContentCount: %d\n" % self.ContentCount
		for i in self.unknown2:
			o += "?: %X\n" % i
		for i in range(self.ContentCount):
			o += '---\n'
			o += "Content: %d\n" % i
			o += str(self.fst_contents[i])
		for i in range(len(self.fe_entries)):
			o += '---\n'
			o += "FE %d\n" % i
			o += str(self.fe_entries[i])
		return o

	def	unpack(self, unpacker):
		self.magic	= unpacker('>I')[0]
		# Check for 'FST\0' magic number
		if (self.magic != 0x46535400):
			return None
		self.unknown1	= unpacker('>I')[0]
		self.ContentCount	= unpacker('>I')[0]
		self.unknown2	= unpacker('>5I')
		fst_contents = []
		for i in range(self.ContentCount):
			e = FST_CONTENT()
			e.unpack(unpacker)
			fst_contents.append(e)
		self.fst_contents = fst_contents
		# Get our first entry so we know how many we have
		fe_entries = []
		root_entry = FE_ENTRY()
		root_entry.unpack(unpacker)
		fe_entries.append(root_entry)
		# Parse the rest of our entries
		for i in range(1, root_entry.f_len):
			e = FE_ENTRY()
			e.unpack(unpacker)
			fe_entries.append(e)
		self.fe_entries = fe_entries
		# Go back and fill in the names
		name_table = unpacker._buffer[unpacker._offset:]
		for e in self.fe_entries:
			for end in range(e.name_offset, e.name_offset + 256):
				if name_table[end] == 0:
					e.fn = name_table[e.name_offset: end].decode('latin-1')
					break
			else:
				e.fn = name_table[e.name_offset: end].decode('latin-1')

# ANCAST info taken from:
# http://wiiubrew.org/wiki/Ancast_Image
class	ANCAST_HEADER():
	def	__init__(self):
		# We hook __getattr__/__setattr__ so we can use "header.body" etc
		# To prevent recursion we need to set our _data member directly.
		self.__dict__['_data'] = collections.OrderedDict()

	def __getattr__(self, name):
		return self._data.get(name, None)

	def __setattr__(self, name, value):
		if global_vars.options.verbose >= DEBUG_LEVEL:
			print("%s.%s=%s" % (__class__.__name__, name, value))
		self._data[name] = value

	def	__str__(self):
		o = ""
		o += str(self._data)
		return o

	def	unpack(self, unpacker):
		self.magic			= unpacker('>I')[0]
		if self.magic != 0xEFA282D9:
			return None
		self.null1			= unpacker('>I')[0]
		self.signature_offset		= unpacker('>I')[0]
		self.null2			= unpacker('>I')[0]
		self.null3			= unpacker('16s')[0]
		unpacker.seek(self.signature_offset)
		self.signature_type		= unpacker('>I')[0]
		if self.signature_type == 1:
			# PPC ancast
			self.signature		= unpacker('%ds' % 0x38)[0]
			self.padding1		= unpacker('%ds' % 0x44)[0]
		elif self.signature_type == 2:
			# ARM
			self.signature		= unpacker('%ds' % 0x100)[0]
			self.padding1		= unpacker('%ds' % 0x7C)[0]
		else:
			print("Unknown signature type 0x%X" % self.signature_type)
		self.null4			= unpacker('>H')[0]
		self.null5			= unpacker('>B')[0]
		self.null6			= unpacker('>B')[0]
		self.unknown			= unpacker('>I')[0]
		self.hash_type			= unpacker('>I')[0]
		self.body_size			= unpacker('>I')[0]
		self.body_hash			= unpacker('20s')[0]
		if self.signature_type == 1:
			self.padding5		= unpacker('%ds' % 0x3C)[0]
		elif self.signature_type == 2:
			self.version		= unpacker('>I')[0]
			self.padding5		= unpacker('%ds' % 0x38)[0]
		self.body			= unpacker('%ds' % self.body_size)[0]
		# Fill in the keys
		if self.signature_type == 1:
			if self.unknown == 0x11:
				# WiiU
				self.key = b'805E6285CD487DE0FAFFAA65A6985E17'
				self.iv  = b'596D5A9AD705F94FE158026FEAA7B887'
			elif self.unknown == 0x13:
				# vWii
				self.key = b'2EFE8ABCEDBB7BAAE3C0ED92FA29F866'
				self.iv  = b'596D5A9AD705F94FE158026FEAA7B887'
		elif self.signature_type == 2:
			if self.unknown == 0x21:
				# ARM
				self.key = b'B5D8AB06ED7F6CFC529F2CE1B4EA32FD'
				self.iv  = b'91C9D008312851EF6B228BF14BAD4322'
