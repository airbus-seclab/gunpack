from defines import *
import mutantX


class ExeUnpacker():

	def __init__(self, command_line, dump_name, unpack_name, file_path):
	
		self.dump_name = dump_name
		self.unpack_name = unpack_name
		self.command_line = command_line
		self.file_path = file_path
		
	def get_dump_name(self):
		return self.dump_name
		
	def get_unpack_name(self):
		return self.unpack_name
	
	def filter_execption(self,process_obj,e):
			
		if e.OwningThread != None:
			return 0

		if process_obj.is_address_in_dll(e.AccessedAddress):
			return 0

		return 1
		
	def set_exeptions_list(self,list):
		self.filtered_exceptions_list = list
	
	def last_execption_address(self):
		return self.filtered_exceptions_list[-1]
	
	def find_oep(self, process_obj):
	
		(oep_virtual, oep_physical) = mutantX.mutantX(self.filtered_exceptions_list)
			
		return oep_virtual