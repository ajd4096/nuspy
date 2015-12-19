
import struct, functools, ctypes

class TMD_CONTENT():
	def __init__(self):
		self.id = 0
		self.index = 0
		self.type = 0
		self.size = 0
		self.sha1_hash = []
	
class TMD_PARSER(TMD_CONTENT):
	""" Parses Wii U TMD """
	def __init__(self, filepath=None):
		self.file = open(filepath, 'rb')
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
		self.tmd_group_ip = 0
		self.tmd_reserved = []
		self.tmd_access_rights = 0
		self.tmd_title_version = 0
		self.tmd_number_of_contents = 0
		self.tmd_boot_index = 0
		self.tmd_padding3 = 0
		self.tmd_hash_table_hash = []
		self.tmd_padding4 = 0
		self.tmd_number_of_contents2 = 0
		self.tmd_content_records_hash = []
		self.tmd_padding4 = []
		self.tmd_contents = []
		
	def readTmdHdr(self):
		self.tmd_signature_type = struct.unpack('>I',self.file.read(4))[0]	#Signature Type
		self.tmd_signature = struct.unpack('>256p',self.file.read(256))
		self.tmd_padding1 = self.file.read(60)
		self.tmd_issuer = 	self.file.read(64)
		self.tmd_version = self.file.read(1)
		self.tmd_ca_crl_version = self.file.read(1)
		self.tmd_signer_crl_version = self.file.read(1)
		self.tmd_padding2 = self.file.read(1)
		self.tmd_system_version = '%016x' % struct.unpack('>Q',self.file.read(8))[0]
		self.tmd_title_id =  '%016x' % struct.unpack('>Q',self.file.read(8))[0]
		self.tmd_title_type = struct.unpack('>I',self.file.read(4))[0]
		self.tmd_group_ip = self.file.read(2)
		self.tmd_reserved = self.file.read(62)
		self.tmd_access_rights = '%08x' % struct.unpack('>I',self.file.read(4))[0]
		self.tmd_title_version = '%04x' % struct.unpack('>H', self.file.read(2))[0]
		self.tmd_number_of_contents = struct.unpack('>H',self.file.read(2))[0]
		self.tmd_boot_index = self.file.read(2)
		self.tmd_padding3 = self.file.read(2)
		self.tmd_hash_table_hash = self.file.read(32)
		self.tmd_padding4 = self.file.read(2)
		self.tmd_number_of_contents2 = self.file.read(2)
		self.tmd_content_records_hash = self.file.read(32)
		self.tmd_contents = []
			
	def ReadContent(self):
		try:
			self.readTmdHdr()			#Read in the TMD Header
			self.file.seek(0xB04,0)		#HARD OFFSET to Contents, May break stuff.
			for content in range(0, self.tmd_number_of_contents):
				tmd_cnt = TMD_CONTENT()
				tmd_cnt.id = '%08x' % struct.unpack('>I',self.file.read(4))[0]
				tmd_cnt.index = struct.unpack('>H',self.file.read(2))[0]
				tmd_cnt.type = struct.unpack('>H',self.file.read(2))[0]
				tmd_cnt.size = struct.unpack('>Q',self.file.read(8))[0]
				tmd_cnt.sha1_hash = struct.unpack('>32s',self.file.read(32))[0]
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
		
			

	

		
		
			
			
