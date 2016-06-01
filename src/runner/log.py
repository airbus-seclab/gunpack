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
from gunpack import Gunpack

def ConvertString(s):
    outp = ""
    for i in s:
        outp += chr(ord(i))
    
    return outp

class Log(Gunpack):

    def __init__(self, file_path):
    
        #build command_line given the binary path
        self.command_line = file_path
        self.set_rwe_policy(1)
        self.set_max_unpack_time(120)
        self.set_initial_nx_state(1)
        
    #handle exceptions sent by the unpacker's core
    def event_handler(self, event_type, event_obj):
        if ( event_type == EVENT_EXCEPTION ):
            exception = event_obj            
            #print "exception received :"
            if ( exception.AccessedType == WRITE_ACCESS ):
                ac_type = "write"
            if ( exception.AccessedType == EXECUTE_ACCESS ): 
                ac_type = "execute"
                
            print "Process (%d), Thread(%d) EXCEPTION %s, address 0x%x" % (exception.ProcessId, exception.ThreadId, ac_type,exception.AccessedAddress)

            AccessedPageBase = exception.AccessedAddress >> 0xC
            EipPageBase = exception.Eip >> 0xC
            
            if ( (AccessedPageBase ==  EipPageBase) and (exception.AccessedType == WRITE_ACCESS)  ):
                print "Process (%d) self modifying code : 0x%x" % ( exception.ProcessId, exception.AccessedAddress )  
            
        if ( event_type == EVENT_CREATE_PROCESS ):
            process = event_obj
            if (process.Create != 0):            
                print "Process (%d) creates a child process (%d)" % (process.ParentId, process.ProcessId)
                self.add_tracked_pid(process.ProcessId)
            
        if ( event_type == EVENT_CREATE_THREAD ):
            thread = event_obj
            if (thread.Create != 0):
                print "Process (%d), Thread(%d) creates a thread (%d)" % (thread.ProcessId, thread.ThreadId, thread.NewThreadId)
                
        if ( event_type == EVENT_LOAD_LIBRARY ):
            library = event_obj
            print "Process (%d) load image %s, base address 0x%x" % (library.ProcessId, ConvertString(library.DllName), library.BaseAddress)

        if ( event_type == EVENT_VIRTUALALLOC ):
            allocation = event_obj
            if ( allocation.result == 0 ):
                print "Process (%d) allocates 0x%x bytes, address 0x%x, rights 0x%x" % (allocation.ProcessId, allocation.RegionSize, allocation.BaseAddress ,allocation.Protect)
            
        if ( event_type == EVENT_VIRTUALPROTECT ):
            protect = event_obj
            if ( protect.result == 0 ):
                print "Process (%d) protects 0x%x bytes, address 0x%x, rights 0x%x" % (protect.ProcessId, protect.RegionSize, protect.BaseAddress ,protect.Protect)
                
        if ( event_type == EVENT_VIRTUALFREE ):
            free = event_obj
            if ( free.result == 0 ):
                print "Process (%d) free 0x%x bytes, address 0x%x, free type 0x%x" % (free.ProcessId, free.RegionSize, free.BaseAddress ,free.FreeType)             

        if ( event_type == EVENT_MAPVIEWOFSECTION ):
            section = event_obj
            if ( section.result == 0 ):
                 print "Process (%d) maps 0x%x bytes in Pid %d, address 0x%x, protect 0x%x, alloc type 0x%x" % (section.ProcessId , section.ViewSize, section.TargetPid, section.BaseAddress ,section.Protect, section.AllocationType)

        if ( event_type == EVENT_TERMINATE_PROCESS ):
            terminate = event_obj
            print "Process (%d) terminates process (%d)" % (terminate.ProcessId, terminate.TargetProcessId)

        return 1
        
    def post_treatment(self):
        
        print "Log post-treatment called !"