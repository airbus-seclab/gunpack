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
from gunpack import *

RWE_PAGE_RWX = 1
INITIAL_READ_ONLY = 1


class Mpress(Gunpack):

    def __init__(self, file_path):
    
        self.command_line = file_path
        self.set_rwe_policy(RWE_PAGE_RWX)
        self.set_max_unpack_time(120)
        self.set_initial_nx_state(INITIAL_READ_ONLY)        
        
    def pre_run(self):
    
        self.packer_oep = self.process.oep()
        self.packer_oep_esp = 0
        self.oep = None
        
        print "Packer Oep : 0x%x" % self.packer_oep
        
    def event_handler(self, event_type, event_obj):
    
        if ( event_type == EVENT_EXCEPTION ):
            e = event_obj
            
            if ( e.AccessedType == EXECUTE_ACCESS ):
                if ( e.Ctx.Esp == self.packer_oep_esp):
                    self.oep = e.Ctx.Eip
                    return 0
                
                if ( e.AccessedAddress == self.packer_oep ):
                    self.packer_oep_esp = e.Ctx.Esp

        return 1
        
    def post_treatment(self):
    
        if ( self.oep != None ):
            dump_name = "%s\dumped.exe" % self.output_directory
            unpack_name = "%s\unpacked.exe" % self.output_directory
            
            self.process.DumpPE( self.process.pid, self.oep, dump_name )
            self.process.Iat_Rebuild( dump_name, unpack_name, self.oep)
            
            print "Process dump with Oep = 0x%x" % self.oep
        else:
            print "Oep not found !"