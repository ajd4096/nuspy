
import struct, functools, ctypes
import binascii
import hashlib

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
	assert False, "Unrecognised signature type"

class unpacker(object):
	def __init__(self, buffer):
		self._buffer = buffer
		self._offset = 0

	def __call__(self, fmt):
		result = struct.unpack_from(fmt, self._buffer, self._offset)
		self._offset += struct.calcsize(fmt)
		return result

	def	seek(self, offset):
		if (offset < len(self._buffer)):
			self._offset = offset
		return self._offset

	def	tell(self):
		return self._offset

class TMD_CONTENT():
	def __init__(self):
		self.id = 0
		self.index = 0
		self.type = 0
		self.size = 0
		self.sha1_hash = []
	
class TMD_PARSER():
	""" Parses Wii U TMD """
	def __init__(self, filepath=None):
		#self.file = open(filepath, 'rb')

		# Read in the entire file, then set up our unpacker
		self.data = open(filepath, 'rb').read()
		self.unpacker = unpacker(self.data)

		self.tmd_signature_type = 0
		self.tmd_signature = []
		self.tmd_padding1 = []
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
		
	def readTmdHdr(self):
		self.tmd_signature_type		= self.unpacker('>I')[0]
		sig_type = get_signature_type('value', self.tmd_signature_type)
		#print(sig_type)
		self.tmd_signature		= self.unpacker('>%ds' % sig_type['size'])[0]
		self.tmd_padding1		= self.unpacker('>%ds' % sig_type['padding'])[0]
		#print("o 0x%X" % self.unpacker._offset)
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
			
	def ReadContent(self):
		try:
			self.readTmdHdr()			#Read in the TMD Header
			self.tmd_contents = []
			for content in range(0, self.tmd_number_of_contents):
				tmd_cnt = TMD_CONTENT()
				tmd_cnt.id		= '%08x' % self.unpacker('>I')[0]
				tmd_cnt.index		= self.unpacker('>H')[0]
				tmd_cnt.type		= self.unpacker('>H')[0]
				tmd_cnt.size		= self.unpacker('>Q')[0]
				tmd_cnt.sha1_hash	= self.unpacker('>32s')[0]
				self.tmd_contents.append(tmd_cnt)
		except Exception as e:
			print(e)
		return

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
		
			

	

		
		
			
			
