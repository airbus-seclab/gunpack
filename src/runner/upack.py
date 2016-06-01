"""
   Copyright 2016 Julien Lenoir / Airbus Group Innovations
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

"""
   Copyright 2016 Julien Lenoir / Airbus Group Innovations
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
from events import *
from gunpack import Gunpack

def ConvertString(s):
    outp = ""
    for i in s:
        outp += chr(ord(i))
    
    return outp

class Upack(Gunpack):

    def __init__(self, file_path):
        self.command_line = file_path
        self.set_rwe_policy(1)
        self.set_max_unpack_time(120)
        self.set_initial_nx_state(0)

        self.bin_name = file_path.split("\\")[-1]
        self.written_pages = []
        self.librairies_loaded = False

    def event_handler(self, event_type, event_obj):
    
        if ( event_type == EVENT_EXCEPTION ):
            e = event_obj

            if ( e.OwningThread != None):
                return 1

            PageBase = e.AccessedAddress >> 0xC
            
            if self.process.is_address_in_dll(e.AccessedAddress):
                return 1
                
            if ( e.AccessedType == WRITE_ACCESS ):
                self.written_pages.append(PageBase)

            if ( (self.librairies_loaded == True) and (e.AccessedType == EXECUTE_ACCESS )):
                if ( PageBase in self.written_pages ):
                    self.oep = e.AccessedAddress
                    return 0

        if ( event_type == EVENT_LOAD_LIBRARY ):
            library = event_obj
            lib_name = ConvertString(library.DllName)

            if ( lib_name.find("System32\\ntdll.dll") != -1 ):
                return 1

            if ( lib_name.find("System32\\kernel32.dll") != -1 ):
                return 1
                     
            if ( lib_name.find("System32\\KernelBase.dll") != -1 ):
                return 1
            
            if ( lib_name.find(self.bin_name) != -1 ):
                return 1
            
            self.librairies_loaded = True

        return 1
        
    def post_treatment(self):
        self.process.DumpPE( self.process.pid, self.oep, "dumped.exe" )
        self.process.Iat_Rebuild( "dumped.exe", "unpacked.exe", self.oep)
        
        print "Process dump with Oep = 0x%x" % self.oep
        
