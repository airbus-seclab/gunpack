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
import mutantX
import time
from gunpack import Gunpack

class Generic(Gunpack):

    def __init__(self, command_line):
        self.command_line = command_line
        # set Gunpack engine params
        self.set_max_unpack_time(30)
        self.set_rwe_policy(1)
        self.set_initial_nx_state(0) 
        self.exception_list = []
    
    def filter_execption(self,e):
        if e.OwningThread != None:
            return 0
        if self.process.is_address_in_dll(e.AccessedAddress):
            return 0

        return 1
        
    def event_handler(self, event_type, event_obj):
        #We are interested only in EXCEPTION events
        if ( event_type == EVENT_EXCEPTION ):
            exception = event_obj
            
            #Filter out loader related exceptions
            if self.filter_execption(exception):
                self.exception_list.append(exception)
                
        #The process tries to exit, stop unpacking
        if ( event_type == EVENT_TERMINATE_PROCESS ):
            terminate = event_obj
            
            if (terminate.TargetProcessId == self.process.pid):
                return 0
                
    def post_treatment(self):
        # Apply MutantX algorithm on exception list to compute OEP
        (Oep_virtual, Oep_physical) = mutantX.mutantX(self.exception_list)
        if (Oep_virtual == 0):
            print "[x] Error : unable to determine Oep"
        
        # Dump PE with new OEP
        self.process.DumpPE( self.process.pid, Oep_virtual, "dumped.exe" )
        self.process.Iat_Rebuild( "dumped.exe", "unpacked.exe", Oep_virtual)
        
        print "[-] Process dumped with Oep : 0x%x" % Oep_virtual
