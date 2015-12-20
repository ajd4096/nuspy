
import struct, functools, ctypes
import binascii
import hashlib

WiiUCommenDevKey = b'\x2F\x5C\x1B\x29\x44\xE7\xFD\x6F\xC3\x97\x96\x4B\x05\x76\x91\xFA'
wiiu_common_key = b'\xD7\xB0\x04\x02\x65\x9B\xA2\xAB\xD2\xCB\x0D\xB2\x7F\xA2\xB6\x56'


def	get_signature_type(key, value):
	# Taken from http://www.3dbrew.org/wiki/Title_metadata
	signature_types = (
		{ 'name':	b'RSA_4096_SHA1',	'value': 0x00010000,	'size': 512,	'padding': 0x3C, },
		{ 'name':	b'RSA_2048_SHA1',	'value': 0x00010001,	'size': 256,	'padding': 0x3C, },
		{ 'name':	b'ECDSA_SHA1',		'value': 0x00010002,	'size': 60,	'padding': 0x40, },
		{ 'name':	b'RSA_4096_SHA256',	'value': 0x00010003,	'size': 512,	'padding': 0x3C, },
		{ 'name':	b'RSA_2048_SHA256',	'value': 0x00010004,	'size': 256,	'padding': 0x3C, },
		{ 'name':	b'ECDSA_SHA256',	'value': 0x00010005,	'size': 60,	'padding': 0x40, },
	)
	for t in signature_types:
		if t[key] == value:
			return t
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
		result = struct.unpack_from(fmt, self._buffer, self._offset)
		self._offset += struct.calcsize(fmt)
		return result

	def	iseof(self):
		if self._offset >= len(self._buffer):
			return True
		return False

	def	seek(self, offset):
		if offset >= 0 and offset < len(self._buffer):
			self._offset = offset
		return self._offset

	def	tell(self):
		return self._offset

class	SIGNATURE():
	def	__init__(self):
		self.sig_type		= 0
		self.sig		= []
		self.padding1		= []

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

class TMD_CONTENT():
	def __init__(self):
		self.id = 0
		self.index = 0
		self.type = 0
		self.size = 0
		self.sha1_hash = []
	
	def	pack(self, packer):
		packer('>I',	int.from_bytes(self.id, 16))
		packer('>H',	self.index)
		packer('>H',	self.type)
		packer('>Q',	self.size)
		packer('>32s',	self.sha1_hash)

	def	unpack(self, unpacker):
		self.id		= '%08x' % unpacker('>I')[0]
		self.index	= unpacker('>H')[0]
		self.type	= unpacker('>H')[0]
		self.size	= unpacker('>Q')[0]
		self.sha1_hash	= unpacker('>32s')[0]

class	TMD_CERT():
	def	__init__(self):
		self.signature		= SIGNATURE()
		self.issuer		= ''
		self.tag		= 0
		self.name		= ''
		self.key		= ''

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
		self.signature.unpack(unpacker)
		self.issuer		= unpacker('>64s')[0].rstrip(b'\x00')
		self.tag		= unpacker('>I')[0]
		self.name		= unpacker('>64s')[0].rstrip(b'\x00')
		self.key		= unpacker('>316s')[0]

class	CETK():
	def	__init__(self):
		self.signature	= SIGNATURE()
		self.issuer			= []
		self.public_key			= []
		self.version			= 0
		self.ca_crl_version		= 0
		self.signer_crl_version		= 0
		self.title_key			= []
		self.reserved1			= 0
		self.title_id			= []
		self.reserved2			= []
		self.ticket_version		= []
		self.reserved3			= []
		self.license_type		= 0
		self.ckey_index			= 0
		self.reserved4			= []
		self.account_id			= []
		self.reserved5			= 0
		self.audit			= 0
		self.reserved6			= []
		self.limits			= []
		self.content_index		= []
		self.certificates = []

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
		unpacker = buffer_unpacker(open(filename, 'rb').read())
		self.unpack(unpacker)

	def	unpack(self, unpacker):
		self.signature.unpack(unpacker)
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
		self.content_index		= unpacker('172s')[0]
		self.certificates = []
		while not unpacker.iseof():
			cert = TMD_CERT()
			cert.unpack(unpacker)
			self.certificates.append(cert)

class TMD_PARSER():
	""" Parses Wii U TMD """
	def __init__(self, filepath=None):
		#self.file = open(filepath, 'rb')

		# Read in the entire file, then set up our unpacker
		self.data = open(filepath, 'rb').read()
		self.unpacker = buffer_unpacker(self.data)

		self.tmd_signature = SIGNATURE()
		self.tmd_issuer = 	[]
		self.tmd_version = 0
		self.tmd_ca_crl_version = 0 
		self.tmd_signer_crl_version = 0
		self.tmd_padding2 = 0
		self.tmd_system_version = 0
		self.tmd_title_id = 0
		self.tmd_title_type = 0
		self.tmd_group_id = 0
		self.tmd_public_save_size = 0
		self.tmd_private_save_size = 0
		self.tmd_reserved1 = []
		self.tmd_srl_flag = 0
		self.tmd_reserved2 = []
		self.tmd_access_rights = 0
		self.tmd_title_version = 0
		self.tmd_number_of_contents = 0
		self.tmd_boot_index = 0
		self.tmd_padding3 = 0
		self.tmd_hash_table_hash = []
		self.tmd_content_info_records = []
		self.tmd_contents = []
		self.certificates = []
		
	def	ReadContent(self):
		self.tmd_signature.unpack(self.unpacker)

		self.tmd_issuer			= self.unpacker('>64s')[0]
		self.tmd_version		= self.unpacker('1c')[0]
		self.tmd_ca_crl_version		= self.unpacker('1c')[0]
		self.tmd_signer_crl_version	= self.unpacker('1c')[0]
		self.tmd_padding2		= self.unpacker('1c')[0]
		self.tmd_system_version		= '%016x' % self.unpacker('>Q')[0]
		self.tmd_title_id		= '%016x' % self.unpacker('>Q')[0]
		self.tmd_title_type		= self.unpacker('>I')[0]
		self.tmd_group_id		= self.unpacker('>H')[0]
		self.tmd_public_save_size	= self.unpacker('>I')[0]
		self.tmd_private_save_size	= self.unpacker('>I')[0]
		self.tmd_reserved1		= self.unpacker('>I')[0]
		self.tmd_srl_flag		= self.unpacker('1c')[0]
		self.tmd_reserved2		= self.unpacker('49s')[0]
		self.tmd_access_rights		= '%08x' % self.unpacker('>I')[0]
		self.tmd_title_version		= '%04x' % self.unpacker('>H')[0]
		self.tmd_number_of_contents	= self.unpacker('>H')[0]
		self.tmd_boot_index		= self.unpacker('>H')[0]
		self.tmd_padding3		= self.unpacker('2s')[0]
		self.tmd_hash_table_hash	= self.unpacker('>32s')[0]

		# Validate the CIR table hash
		offset = self.unpacker.tell()
		cir_table_hash = hashlib.sha256(self.data[offset : offset + 0x24 * 64]).digest()
		if (self.tmd_hash_table_hash != cir_table_hash):
			print("Hash mismatch for CIR table")
			print("Expected: %s" % self.tmd_hash_table_hash)
			print("Found: %s" % cir_table_hash)
		else:
			print("Hash ok for CIR table")

		# Read in all the content info records
		self.tmd_content_info_records = []
		for i in range(64):
			(cir_offset, cir_count, cir_hash)	= self.unpacker('>HH32s')
			self.tmd_content_info_records.append((cir_offset, cir_count, cir_hash))

		# Validate the CIR entry hashes
		# (Guessed starting offset, only ever seen the 1st CIR used to hash all the CCR)
		offset = self.unpacker.tell()
		for i in range(64):
			(cir_offset, cir_count, cir_hash) = self.tmd_content_info_records[i]
			if cir_count:
				start = offset + cir_offset * 0x30
				ccr_hash = hashlib.sha256(self.data[start : start + cir_count * 0x30]).digest()
				if ccr_hash != cir_hash:
					print("Hash mismatch for CIR entry %d" %  i)
					print("Expected: %s" % cir_hash)
					print("Found: %s" % ccr_hash)
				else:
					print("Hash ok for CIR entry %d" %  i)

		# Read in the content records
		self.tmd_contents = []
		for content in range(0, self.tmd_number_of_contents):
			tmd_cnt = TMD_CONTENT()
			tmd_cnt.unpack(self.unpacker)
			self.tmd_contents.append(tmd_cnt)

		# Read in any certificates after
		self.certificates = []
		while not self.unpacker.iseof():
			print("Found cert at 0x%X" % self.unpacker.tell())
			cert = TMD_CERT()
			cert.unpack(self.unpacker)
			self.certificates.append(cert)



class FST_CONTENT():
	def __init__(self):
		self.unk = 0
		self.size = 0
		self.unk2 = 0
		self.unklist = []
		
class FE_ENTRY():
	def __init__(self):
		self.type = 0
		self.name_offset = 0
		self.f_off = 0
		self.f_len = 0
		self.parent = ''
		self.next = ''
		self.flags = 0
		self.content_id = 0
		self.fn = ''

class FST_PARSER(FST_CONTENT, FE_ENTRY):
	def __init__(self, data):
		self.data = data
		self.mgc_num = functools.reduce(lambda x,y: (x << 8) + y, list(self.data[:4]))
		self.unk = functools.reduce(lambda x,y: (x << 8) + y, list(self.data[4:8]))
		self.ent_cnt = functools.reduce(lambda x,y: (x << 8) + y, list(self.data[8:12]))
		self.unk_lst = self.data[12:32]
		self.fst_contents = []
		self.fe_entry_start = 0
		self.fst_ent_cnt = 0
		self.fe_entries = []
		self.name_off = 0

	
	def GetFileListFromFST(self):
		""" Generates file names and and them to content list
		Adds filenames to each file_entry and adds its parent directory
		and next directory
		"""
		content_index = []
		entries = len(self.fe_entries)
		for fe in self.fe_entries:
			f_off = self.name_off + fe.name_offset			
			fname = []
			for i in range(256):
				fname.append(self.data[f_off + i])
				if self.data[f_off + i + 1] == 0:
					break
			fn = ''.join(map(chr,fname))
			if fn[1:] == 'code':
				fe.fn = fn[1:]
			else:
				fe.fn = fn
			content_index.append(fe.fn)
			if fe == 0:
				fe.f_off = fe.f_off << 5

		for fe in self.fe_entries:
			if fe.type == 1:
				try:
					fe.parent = content_index[fe.f_off]
					if fe.f_len == self.fst_ent_cnt:
						fe.next = "EOD"
						#print(fe.fn, fe.f_len)
					else:
						fe.next = content_index[fe.f_len]
				except Exception as e:
					print("ERROR:", fe.fn, fe.f_len, entries, self.fst_ent_cnt )
		return
		
	def ReadFST(self):
		myfst = FST_CONTENT()
		for i in range(self.ent_cnt):
			s_off = 0x20 + (i * 0x20)
			myfst.unk = functools.reduce(lambda x,y: (x << 8) + y, list(self.data[s_off:s_off+4]))
			s_off += 0x4
			myfst.size = functools.reduce(lambda x,y: (x << 8) + y, list(self.data[s_off:s_off+4]))
			s_off += 0x4
			myfst.unk2 = functools.reduce(lambda x,y: (x << 8) + y, list(self.data[s_off:s_off+4]))
			s_off += 0x4
			for j in range(0,0x14,0x04):
				s_off += 0x4
				myfst.unklist.append(functools.reduce(lambda x,y: (x << 8) + y, list(self.data[s_off + j:s_off+j + 4])))
			self.fst_contents.append(myfst)
		self.fe_entry_start = (0x20 + (self.ent_cnt * 0x20))
		self.fst_ent_cnt = functools.reduce(lambda x,y: (x << 8) + y, list(self.data[(self.fe_entry_start + 8):(self.fe_entry_start + 8 + 4)]))
		self.name_off = (0x20 + (self.ent_cnt *0x20) + (self.fst_ent_cnt * 0x10))
		for i in range(0,self.fst_ent_cnt):
			myfe = FE_ENTRY()
			s_off = self.fe_entry_start + (i * 0x10)
			myfe.type = self.data[s_off:(s_off + 0x01)][0]
			s_off += 0x01
			myfe.name_offset = functools.reduce(lambda x,y: (x << 8) + y, list(self.data[s_off:s_off+3]))
			s_off += 0x03
			myfe.f_off = functools.reduce(lambda x,y: (x << 8) + y, list(self.data[s_off:s_off+4]))
			s_off += 0x04
			myfe.f_len = functools.reduce(lambda x,y: (x << 8) + y, self.data[s_off:s_off+4])
			s_off += 0x04
			myfe.flags = functools.reduce(lambda x,y: (x << 8) + y, list(self.data[s_off:s_off+2]))
			s_off += 0x02
			myfe.content_id = functools.reduce(lambda x,y: (x << 8) + y, list(self.data[s_off:s_off+2]))
			s_off += 0x02
			self.fe_entries.append(myfe)
		return
