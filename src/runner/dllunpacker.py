"""
   Copyright 2015 Julien Lenoir / Airbus Group Innovations
   contact: julien.lenoir@airbus.com
"""
"""
	This file is part of Gunpack.

	Gunpack is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	Gunpack is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Gunpack.  If not, see <http://www.gnu.org/licenses/>.
"""

from defines import *
import mutantX

class PageAccess():
	def __init__(self):
		self.LastWritten = 0
		self.LastExec = 0
		self.ExecAddress = 0
		
	def __str__(self):
		s = ""
		s += "LastWritten : %d " % self.LastWritten
		s += "LastExec : %d " % self.LastExec
		s += "ExecAddress : %x " % self.ExecAddress
		return s


class DllUnpacker():

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
			
		if e.OwningThread == None:
			return 0
		
		if (e.DllName != self.file_path):
			return 0
			
		if (process_obj.is_address_in_dll(e.AccessedAddress)):
			return 0

		return 1
		
	def set_exeptions_list(self,list):
		self.filtered_exceptions_list = list
	
	def last_execption_address(self):
		return self.filtered_exceptions_list[-1]
	
	def find_oep(self, process_obj):
	
		(oep_virtual, oep_physical) = mutantX.mutantX(self.filtered_exceptions_list)
			
		return oep_virtual