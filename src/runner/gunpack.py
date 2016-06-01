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

import ctypes
import os
import time
import pefile
from scylla import Scylla
from process import Process
from threading import Thread
from defines import *
from events import *
from process import *
import sys

try:
    from lib.common.defines import KERNEL32, DWORD, LPVOID, PROCESS_INFORMATION, STARTUPINFO, MEMORY_BASIC_INFORMATION, LONG, BYTE, CREATE_SUSPENDED, MEM_IMAGE, MEM_PRIVATE, MEM_COMMIT, HANDLE, LPTSTR, MODULEENTRY32
except ImportError:
    from defines import KERNEL32, DWORD, LPVOID, PROCESS_INFORMATION, STARTUPINFO, MEMORY_BASIC_INFORMATION, LONG, BYTE, CREATE_SUSPENDED, MEM_IMAGE, MEM_PRIVATE, MEM_COMMIT, HANDLE, LPTSTR, MODULEENTRY32

ONE_SEC = 1000

#############################
#### Windows internal stuff
#############################


PAGE_SIZE = 0x1000
NULL = 0

GENERIC_READ              = 0x80000000
GENERIC_WRITE             = 0x40000000

OPEN_EXISTING             = 3

WAIT_TIMEOUT              = 0x102
WAIT_ABANDONED            = 0x80
WAIT_OBJECT_0             = 0

PROCESS_ALL_ACCESS        = 0x001FFFFF

PIPE_ACCESS_INBOUND       = 0x00000001
PIPE_ACCESS_DUPLEX        = 0x00000003
PIPE_TYPE_MESSAGE         = 0x00000004
PIPE_READMODE_MESSAGE     = 0x00000002
PIPE_WAIT                 = 0x00000000
PIPE_UNLIMITED_INSTANCES  = 0x000000ff
PIPE_TYPE_BYTE            = 0x00000000
PIPE_READMODE_BYTE        = 0x00000000


MAX_PATH = 260
INVALID_HANDLE_VALUE = HANDLE(-1)

#############################
#### Driver communication
#############################

IOCTL_SETUP_STUFF =         0x9C40E000
IOCTL_CLEANUP =             0x9C40E004
IOCTL_GET_EXCEPTION =       0x9C40E008
IOCTL_GET_EXCEPTION_COUNT = 0x9C40E00C
IOCTL_SUSPEND_TRACKED =     0x9C40E010
IOCTL_RETRIEVE_EXCEPTION =  0x9C40E014
IOCTL_UNTRACK_AND_RESUME_PROCESSES = 0x9C40E018
IOCTL_ADD_TRACKED = 0x9C40E01C

RWE_SINGLE_STEP = 0
RWE_PAGE_RWX = 1

INITIAL_EXECUTABLE = 0
INITIAL_READ_ONLY = 1

class PID_STRUCT(ctypes.Structure):
    _fields_ = [("do_log", DWORD),
                ("RWEPolicy", DWORD),
                ("InitiallyNonExecutable", DWORD),                
                ("UserlandNotidyEvent", HANDLE), 
                ("TargetProcessHandle", HANDLE)]

class UnpackerException(Exception):
   pass 

class Gunpack():

    def __init__(self, log, filename, scylla_dll, unpacker, kernel_log):
        self.filename = filename
        self.log = log
        
        self.kernel_log = kernel_log
        self.process_running = False
        self.hUnpackEvent = HANDLE(0)
        
        set.output_directory = "."
        self.rwe_policy = RWE_SINGLE_STEP
        self.initial_nx_state  = INITIAL_READ_ONLY

    def set_params(self, log, device_name, kernel_log, output_directory):
    
        self.device_name = device_name
        self.log = log
        self.kernel_log = kernel_log
        self.output_directory = output_directory
        
    def set_max_unpack_time(self, max_unpack_time):
        self.max_unpack_time = max_unpack_time * 1000
        
    def set_rwe_policy(self, rwe_policy):
        self.rwe_policy = rwe_policy
        
    def set_initial_nx_state(self, initial_nx_state):
        self.initial_nx_state = initial_nx_state        

    def pipe_reader_thread(self):
        
        evt_header = EVENT_HEADER()
        nbRead = DWORD(0)

        while( self.thread_running ):

            valid_object = True
            
            #Wait for the driver to signal an event is ready for retrieval
            r = KERNEL32.WaitForSingleObject(self.UserlandNotidyEvent, INFINITE)
            if (r == WAIT_OBJECT_0):
                
                #An event has arrived, request it to the driver
                ReceiveBuffer = ctypes.create_string_buffer(1024)
                BytesReturned = DWORD(0)
                success = KERNEL32.DeviceIoControl(self.hdevice,IOCTL_RETRIEVE_EXCEPTION,NULL,0,ctypes.byref(ReceiveBuffer),ctypes.sizeof(ReceiveBuffer),ctypes.byref(BytesReturned),0)
                if not(success):
                    self.log.error("DeviceIoControl failed")
                    raise UnpackerException("DeviceIoControl failed")
                
                header_size = ctypes.sizeof(EVENT_HEADER)
                
                #Ensure there is a header
                if ( BytesReturned.value < header_size ):
                    self.log.error( "Did not receive enough data from driver (%d bytes)" % BytesReturned.value )
                    continue    
                
                #Copy the data in a EVENT_HEADER object
                ctypes.memmove( ctypes.addressof(evt_header), ReceiveBuffer[0:header_size], header_size )
                
                #Ensure it is a known event
                if not(Events.has_key( evt_header.event_type)):
                    self.log.error("Received unknown event with type : %d" % evt_header.event_type)
                    continue                

                #Ensure the object fits in the buffer
                n_remaining_bytes = BytesReturned.value - header_size
                
                event_class = Events[evt_header.event_type]
                
                if ( n_remaining_bytes != ctypes.sizeof(event_class) ):
                    self.log.error("Wrong event size. Received %d bytes, expected %d bytes" % (n_remaining_bytes, ctypes.sizeof(event_class)) )
                    continue     
                
                event_obj = event_class()
                
                # "cast" the buffer in the appropriate event class
                ctypes.memmove( ctypes.addressof(event_obj), ReceiveBuffer[header_size:], ctypes.sizeof(event_class) )
                
                #call the user defined event handler
                result = self.event_handler(evt_header.event_type , event_obj)
                if (result == 0):
                    self.stop()
                    return


    def stop(self):
        KERNEL32.SetEvent(self.hUnpackEvent)

    #Function called after each event
    def event_handler(self, event_type, event_obj):        
        pass
        
    #Function called once process is suspended
    def post_treatment(self):
        pass
        
    #Function called juste after target process creation but just before it is
    #being started
    def pre_run(self):
        pass
        
    def add_tracked_pid(self, pid):
        #Initiate driver's state and communication mecanisms
        BytesReturned = DWORD(0)
        pid = DWORD(pid)
        success = KERNEL32.DeviceIoControl(self.hdevice,IOCTL_ADD_TRACKED,ctypes.byref(pid),ctypes.sizeof(pid),NULL,0,ctypes.byref(BytesReturned),0)
        if not(success):
            self.log.error("DeviceIoControl failed")
            raise UnpackerException("DeviceIoControl failed")    

    
    def run(self, waiting_time):
    
        # Open driver device
        self.hdevice = KERNEL32.CreateFileA(self.device_name, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
        if self.hdevice == INVALID_HANDLE_VALUE:
            self.log.error("CreateFileA failed with error : 0x%x" % KERNEL32.GetLastError())
            quit()

        self.log.info("Driver device file opened, handle = %x" % self.hdevice)    
    
        #todo : build command line
        self.process = Process(self.command_line, self.log)

        self.process.create_suspended()
        
        self.pre_run()
        
        self.log.info("Target process handle value is 0x%x" % self.process.process_handle)
        
        self.thread_running = True
        thread = Thread(target = self.pipe_reader_thread, args = ())
        
        #Create an unpack event which will be signaled when the
        self.hUnpackEvent = KERNEL32.CreateEventA(NULL,0,0,"DaEvent")
        self.UserlandNotidyEvent = KERNEL32.CreateEventA(NULL,0,0,"UserlandNotidyEvent")
        
        #Struct sent to the driver
        MyPidStruct = PID_STRUCT()
        MyPidStruct.do_log = self.kernel_log
        MyPidStruct.RWEPolicy = self.rwe_policy;
        MyPidStruct.InitialNXState = self.initial_nx_state;
        MyPidStruct.UserlandNotidyEvent = self.UserlandNotidyEvent
        MyPidStruct.TargetProcessHandle = self.process.process_handle
        
        #Initiate driver's state and communication mecanisms
        BytesReturned = DWORD(0)
        success = KERNEL32.DeviceIoControl(self.hdevice,IOCTL_SETUP_STUFF,ctypes.byref(MyPidStruct),ctypes.sizeof(MyPidStruct),NULL,0,ctypes.byref(BytesReturned),0)
        if not(success):
            self.log.error("DeviceIoControl failed")
            raise UnpackerException("DeviceIoControl failed")
            
        thread.start()

        #Resume main process thtread
        self.process.resume()
        self.log.info("Main thread resumed")

        #Wait for unpacking to terminate
        r = KERNEL32.WaitForSingleObject(self.hUnpackEvent,self.max_unpack_time)
        if (r == WAIT_ABANDONED ):
            self.log.error("Wait abandoned, something went wrong")
            raise UnpackerException("Wait abandoned, something went wrong")
            
        if (r == WAIT_TIMEOUT):
            self.log.info("Wait timed out")
            self.log.info("Thread suspended")

        if (r == WAIT_OBJECT_0):
            self.log.info("Event signaled")
        
        BytesReturned = DWORD(0)
        success = KERNEL32.DeviceIoControl(self.hdevice,IOCTL_SUSPEND_TRACKED,NULL,0,NULL,0,ctypes.byref(BytesReturned),0)
        if not(success):
            self.log.error("DeviceIoControl failed")
            raise UnpackerException("DeviceIoControl failed")
            
        self.thread_running = False
        
        result = self.post_treatment()
        
        BytesReturned = DWORD(0)
        success = KERNEL32.DeviceIoControl(self.hdevice,IOCTL_UNTRACK_AND_RESUME_PROCESSES,NULL,0,NULL,0,ctypes.byref(BytesReturned),0)
        if not(success):
            self.log.error("DeviceIoControl failed")
            raise UnpackerException("DeviceIoControl failed")
        
        BytesReturned = DWORD(0)
        success = KERNEL32.DeviceIoControl(self.hdevice,IOCTL_CLEANUP,NULL,0,NULL,0,ctypes.byref(BytesReturned),0)
        if not(success):
            self.log.error("DeviceIoControl failed")
            raise UnpackerException("DeviceIoControl failed")
        
        KERNEL32.CloseHandle(self.hdevice)
        KERNEL32.CloseHandle(self.UserlandNotidyEvent)
        
        self.process.terminate()
        
        KERNEL32.ExitProcess(0)
