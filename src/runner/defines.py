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

from ctypes import *

NTDLL    = windll.ntdll
KERNEL32 = windll.kernel32
ADVAPI32 = windll.advapi32
USER32   = windll.user32
PSAPI    = windll.psapi

CHAR      = c_char
BYTE      = c_ubyte
WORD      = c_ushort
DWORD     = c_ulong
LONG      = c_ulong
LPBYTE    = POINTER(c_ubyte)
LPTSTR    = POINTER(c_char)
HANDLE    = c_void_p
PVOID     = c_void_p
LPVOID    = c_void_p
UINT_PTR  = c_ulong
SIZE_T    = c_ulong
HMODULE   = c_void_p
NULL      = c_int(0)

DEBUG_PROCESS             = 0x00000001
CREATE_NEW_CONSOLE        = 0x00000010
CREATE_SUSPENDED          = 0x00000004
DBG_CONTINUE              = 0x00010002
INFINITE                  = 0xFFFFFFFF
PROCESS_ALL_ACCESS        = 0x001F0FFF
THREAD_ALL_ACCESS         = 0x001f03ff
TOKEN_ALL_ACCESS          = 0x000F01FF
SE_PRIVILEGE_ENABLED      = 0x00000002
STILL_ACTIVE              = 0x00000103

PAGE_EXECUTE_READWRITE    = 0x00000040
PAGE_EXECUTE              = 0x00000010
PAGE_EXECUTE_READ         = 0x00000020
PAGE_READONLY             = 0x00000002
PAGE_READWRITE            = 0x00000004

MEM_COMMIT                = 0x00001000
MEM_RESERVE               = 0x00002000
MEM_DECOMMIT              = 0x00004000
MEM_RELEASE               = 0x00008000
MEM_RESET                 = 0x00080000

MEM_IMAGE                 = 0x01000000
MEM_MAPPED                = 0x00040000
MEM_PRIVATE               = 0x00020000
MEM_FREE                  = 0x00010000

PAGE_NOACCESS             = 0x00000001
PAGE_READONLY             = 0x00000002
PAGE_READWRITE            = 0x00000004
PAGE_WRITECOPY            = 0x00000008
PAGE_EXECUTE              = 0x00000010
PAGE_EXECUTE_READ         = 0x00000020
PAGE_EXECUTE_READWRITE    = 0x00000040
PAGE_EXECUTE_WRITECOPY    = 0x00000080
PAGE_GUARD                = 0x00000100
PAGE_NOCACHE              = 0x00000200
PAGE_WRITECOMBINE         = 0x00000400

PIPE_ACCESS_INBOUND       = 0x00000001
PIPE_ACCESS_OUTBOUND      = 0x00000002
PIPE_ACCESS_DUPLEX        = 0x00000003
PIPE_TYPE_MESSAGE         = 0x00000004
PIPE_READMODE_MESSAGE     = 0x00000002
PIPE_WAIT                 = 0x00000000
PIPE_UNLIMITED_INSTANCES  = 0x000000ff
PIPE_TYPE_BYTE            = 0x00000000
PIPE_READMODE_BYTE        = 0x00000000
FILE_FLAG_WRITE_THROUGH   = 0x80000000
INVALID_HANDLE_VALUE      = 0xffffffff
ERROR_BROKEN_PIPE         = 0x0000006d
ERROR_MORE_DATA           = 0x000000EA
ERROR_PIPE_CONNECTED      = 0x00000217

TH32CS_SNAPMODULE         = 0x00000008

WAIT_TIMEOUT              = 0x00000102

FILE_ATTRIBUTE_HIDDEN     = 0x00000002

WM_GETTEXT                = 0x0000000D
WM_GETTEXTLENGTH          = 0x0000000E
BM_CLICK                  = 0x000000F5


WRITE_ACCESS				= 	1
EXECUTE_ACCESS				= 	8


class MODULEINFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", PVOID),
        ("SizeOfImage", DWORD),
        ("EntryPoint", LPVOID),
    ]

class THE_CONTECXT(Structure):
    _fields_ = [
        ("Eax", LONG),
        ("Ecx", LONG),
        ("Edx", LONG),
        ("Ebx", LONG),
        ("Esp", LONG),
        ("Esi", LONG),
        ("Edi", LONG),
        ("Eip", LONG),
    ]

class STARTUPINFO(Structure):
    _fields_ = [
        ("cb",            DWORD),
        ("lpReserved",    LPTSTR),
        ("lpDesktop",     LPTSTR),
        ("lpTitle",       LPTSTR),
        ("dwX",           DWORD),
        ("dwY",           DWORD),
        ("dwXSize",       DWORD),
        ("dwYSize",       DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags",       DWORD),
        ("wShowWindow",   WORD),
        ("cbReserved2",   WORD),
        ("lpReserved2",   LPBYTE),
        ("hStdInput",     HANDLE),
        ("hStdOutput",    HANDLE),
        ("hStdError",     HANDLE),
    ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),
    ]

class LUID(Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG),
    ]

class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]

class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES),
    ]

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]

class PROC_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
    ]

class SYSTEM_INFO_UNION(Union):
    _fields_ = [
        ("dwOemId", DWORD),
        ("sProcStruc", PROC_STRUCT),
    ]

class SYSTEM_INFO(Structure):
    _fields_ = [
        ("uSysInfo", SYSTEM_INFO_UNION),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", DWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]
	
class MODULEENTRY32(Structure):
    _fields_ = [ ( 'dwSize' , LONG ) ,
                ( 'th32ModuleID' , LONG ),
                ( 'th32ProcessID' , LONG ),
                ( 'GlblcntUsage' , LONG ),
                ( 'ProccntUsage' , LONG ) ,
                ( 'modBaseAddr' , LONG ) ,
                ( 'modBaseSize' , LONG ) ,
                ( 'hModule' , LPVOID ) ,
                ( 'szModule' , CHAR * 256 ),
                ( 'szExePath' , CHAR * 260 ) ]