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
from threading import Thread
from defines import *

MAX_PATH = 260

EVENT_EXCEPTION           = 0
EVENT_SYSCALL             = 1
EVENT_CREATE_PROCESS      = 2
EVENT_CREATE_THREAD       = 3
EVENT_LOAD_LIBRARY        = 4
EVENT_TERMINATE_PROCESS   = 5
EVENT_VIRTUALALLOC        = 6
EVENT_VIRTUALPROTECT      = 7
EVENT_VIRTUALFREE         = 8
EVENT_MAPVIEWOFSECTION    = 9

class EVENT_HEADER(ctypes.Structure):
    _fields_ = [("event_type", WORD),
                ("event_size", WORD)]

class EXCEPTION_STRUCT(ctypes.Structure):
    _fields_ = [ ("Ctx", THE_CONTECXT),
                ("ProcessId", LPVOID),
                ("ThreadId", LPVOID),
                ("AccessedAddress", LPVOID),
                ("AccessedType",LONG),
                ("InDllLoad",LONG),
                ("LockCount",LONG),
                ("RecursionCount",LONG),
                ("OwningThread",HANDLE),
                ("CurrentThread",HANDLE),
                ("Physicallow",LONG),
                ("Physicalhigh",LONG),
                ("DllBaseAddress",LONG)]

class PROCESS_STRUCT(ctypes.Structure):
    _fields_ = [("ParentId", LPVOID),
                ("ProcessId",LPVOID),
                ("Create",LONG)]

class THREAD_STRUCT(ctypes.Structure):
    _fields_ = [("ProcessId", LPVOID),
                ("NewThreadId",LPVOID),
                ("ThreadId",LPVOID),
                ("Create",LONG)]

class IMAGE_STRUCT(ctypes.Structure):
    _fields_ = [("BaseAddress", LPVOID),
                ("ProcessId", LPVOID),
                ("DllName",ctypes.c_wchar * MAX_PATH)]
  
class TERMINATEPROCESS_STRUCT(ctypes.Structure):
    _fields_ = [("ProcessId", LPVOID),
                ("TargetProcessId",LPVOID)]

class VIRTUALALLOC_STRUCT(ctypes.Structure):
    _fields_ = [("ParentId", LPVOID),
                ("ThreadId",LPVOID),    
                ("ProcessId",LPVOID),
                ("BaseAddress",LPVOID),
                ("RegionSize",LONG),
                ("AllocationType",LONG),
                ("Protect",LONG),
                ("result",LONG)]
                
class VIRTUALPROTECT_STRUCT(ctypes.Structure):
    _fields_ = [("ParentId", LPVOID),
                ("ProcessId",LPVOID),
                ("BaseAddress",LPVOID),
                ("RegionSize",LONG),
                ("Protect",LONG),
                ("result",LONG)]

class VIRTUALFREE_STRUCT(ctypes.Structure):
    _fields_ = [("ProcessId",LPVOID),
                ("BaseAddress",LPVOID),
                ("RegionSize",LONG),
                ("FreeType",LONG),
                ("result",LONG)]
                
class MAPVIEWOFSECTION_STRUCT(ctypes.Structure):
    _fields_ = [("ProcessId",LPVOID),
                ("TargetPid",LPVOID),
                ("BaseAddress",LPVOID),
                ("ZeroBits",LONG),
                ("ViewSize",LONG),
                ("AllocationType",LONG),
                ("Protect",LONG),
                ("result",LONG)]

Events = {EVENT_EXCEPTION : EXCEPTION_STRUCT,
        EVENT_CREATE_PROCESS : PROCESS_STRUCT,
        EVENT_CREATE_THREAD : THREAD_STRUCT,
        EVENT_LOAD_LIBRARY : IMAGE_STRUCT,
        EVENT_TERMINATE_PROCESS : TERMINATEPROCESS_STRUCT,
        EVENT_VIRTUALALLOC : VIRTUALALLOC_STRUCT,
        EVENT_VIRTUALPROTECT : VIRTUALPROTECT_STRUCT,
        EVENT_VIRTUALFREE : VIRTUALFREE_STRUCT,
        EVENT_MAPVIEWOFSECTION : MAPVIEWOFSECTION_STRUCT,
        }