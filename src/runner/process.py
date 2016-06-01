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
import pefile
from defines import *

SCY_ERROR_SUCCESS = 0
PAGE_SIZE = 0x1000

class Process():
    def __init__(self, path, log):
        self.path = path
        self.log = log
        self.pid = 0
        self.process_handle = 0
        self.thread_handle = 0
        self.main_module_name = self.path.split("\\")[-1]
        self.modules = None
        # Constants
        self.SIZEOF_PE_BUFFER = 1024
        
        self.pe = pefile.PE(path)

        scylla_dll = ctypes.WinDLL("Scylla_x86.dll")
        
        LPDWORD = ctypes.POINTER(DWORD)
        CHAR = ctypes.c_char
        LPSTR = ctypes.POINTER(CHAR)
        

        self.ScyllaDumpProcessA = scylla_dll.ScyllaDumpProcessA
        self.ScyllaDumpProcessA.argtypes = [DWORD,LPVOID,LPVOID,LPVOID,LPTSTR]
        self.ScyllaDumpProcessA.restype = DWORD

        self.ScyllaIatSearch = scylla_dll.ScyllaIatSearch
        self.ScyllaIatSearch.argtypes = [DWORD,LPVOID,LPDWORD,DWORD,BYTE]
        self.ScyllaIatSearch.restype = DWORD

        self.ScyllaIatFixAutoW = scylla_dll.ScyllaIatFixAutoW
        self.ScyllaIatFixAutoW.argtypes = [LPVOID,DWORD,DWORD,LPTSTR,LPTSTR]
        self.ScyllaIatFixAutoW.restype = DWORD

        self.ScyllaRebuildFileA = scylla_dll.ScyllaRebuildFileA
        self.ScyllaRebuildFileA.argtypes = [LPTSTR,DWORD,DWORD,DWORD]
        self.ScyllaRebuildFileA.restype = DWORD


    def get_loaded_section_info(self, i):
    
        # Retrieve section from PE file
        section = self.pe.sections[i]
        
        # Retrieve main module base address
        module_base = self.pe.OPTIONAL_HEADER.ImageBase
        
        # Rebase section information before retrieving it
        return (section.Name, section.VirtualAddress + module_base, section.Misc_VirtualSize)
        
        
    def create_suspended(self):
        pi = PROCESS_INFORMATION()
        si = STARTUPINFO()
        si.cb = ctypes.sizeof(si)
        
        success = KERNEL32.CreateProcessA(ctypes.c_char_p(0),
                                                 ctypes.c_char_p(self.path),
                                                 0,
                                                 0,
                                                 0,
                                                 CREATE_SUSPENDED,
                                                 0,
                                                 0,
                                                 ctypes.byref(si),
                                                 ctypes.byref(pi))

        if success:
            self.pid = pi.dwProcessId
            self.thread_handle = pi.hThread
        else:
            raise UnpackerException("CreateProcessA failed !")
            return 0
            
        #Re-open process with all access rights
        self.process_handle = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS,0,self.pid)
        if self.process_handle == INVALID_HANDLE_VALUE:
            raise UnpackerException("OpenProcess failed on pid=%d with error code=0x%x" % (self.pid,KERNEL32.GetLastError()))
            return 0            
        
        return 1

    def resume(self):
        return KERNEL32.ResumeThread(self.thread_handle)

    def suspend(self):
        return KERNEL32.SuspendThread(self.thread_handle)

    def terminate(self):
        KERNEL32.TerminateProcess(self.process_handle,0)
        KERNEL32.CloseHandle(self.process_handle)
        
    def find_module_by_address(self, addr):
        result = None
        hModuleSnap = LPVOID(0)
        me32 = MODULEENTRY32()
        me32.dwSize = ctypes.sizeof(MODULEENTRY32)

        hModuleSnap = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid)
        if hModuleSnap == -1:
            return result

        module = KERNEL32.Module32First(hModuleSnap, ctypes.pointer(me32))
        if module == 0 :
            KERNEL32.CloseHandle(hModuleSnap)
            return result

        while module :
            if me32.modBaseAddr < addr and addr < (me32.modBaseAddr + me32.modBaseSize):
                result = me32
                module = False
                continue
                
            module = KERNEL32.Module32Next(hModuleSnap , ctypes.pointer(me32))

        KERNEL32.CloseHandle(hModuleSnap)
        return result
        
    def find_module_by_name(self,name):
        if self.modules == None:
            self.build_modules_dict()

        print self.modules
        return self.modules[name.lower()]
     
    
    def build_module_base_address(self):
    
        modInfo = MODULEINFO()
        hModules = HMODULE()
        bytesNeeded = DWORD(0)
        result = 0
        
        r = PSAPI.EnumProcessModules(self.process_handle, ctypes.addressof(hModules), ctypes.sizeof(hModules), ctypes.byref(bytesNeeded) )
        if ( r != 0):
            r = PSAPI.GetModuleInformation(self.process_handle, hModules, ctypes.pointer(modInfo), ctypes.sizeof(MODULEINFO))
            if (r == True):
                print modInfo
                result = modInfo.lpBaseOfDll
            else:
                self.log.warn("GetModuleInformation failed, Error=0x%x", KERNEL32.GetLastError())
        else:
            self.log.warn("EnumProcessModules failed, Error=0x%x", KERNEL32.GetLastError())
            
        return result
                
    def build_modules_dict(self):
    
        self.modules = {}
        result = None
        hModuleSnap = LPVOID(0)
        me32 = MODULEENTRY32()
        me32.dwSize = ctypes.sizeof(MODULEENTRY32)

        hModuleSnap = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid)
        if hModuleSnap == -1:
            #self.log.warn("CreateToolhelp32Snapshot failed, Error=0x%x", KERNEL32.GetLastError())
            return result

        module = KERNEL32.Module32First(hModuleSnap, ctypes.pointer(me32))
        if module == 0 :
            self.log.warn("Module32First failed")
            KERNEL32.CloseHandle(hModuleSnap)
            return result

        self.modules[me32.szModule.lower()] = me32            
            
        while module :
            me32 = MODULEENTRY32()
            me32.dwSize = ctypes.sizeof(MODULEENTRY32)            
            module = KERNEL32.Module32Next(hModuleSnap , ctypes.pointer(me32))
            self.modules[me32.szModule.lower()] = me32    
            
        KERNEL32.CloseHandle(hModuleSnap)
        return result
        
    def is_address_in_other_module(self,addr,module_name):
        
        if self.modules == None:
            self.build_modules_dict()
            
        mod_name_lower = module_name.lower()
            
        for name in self.modules.keys():
            if name != mod_name_lower:
                module = self.modules[name]
                (addr_low, addr_high) = (module.modBaseAddr, module.modBaseAddr + module.modBaseSize)
                if ( addr_low <= addr ) and ( addr < addr_high ):
                    return 1
                    
        return 0
        
    def is_address_in_dll(self,addr):    
        return self.is_address_in_other_module(addr,self.main_module_name)
        
    def oep(self):
        pe = pefile.PE(self.path)
        oep = self.pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        return oep

    def LocatePeBase(self, current_base):
        MemInfo = MEMORY_BASIC_INFORMATION()
        Pe_buffer = ctypes.create_string_buffer(self.SIZEOF_PE_BUFFER)
        BytesToRead = LONG()

        while True:
           r = KERNEL32.VirtualQueryEx(self.process_handle, current_base, ctypes.byref(MemInfo), 
                                                             ctypes.sizeof(MemInfo))
           if r == 0:
               self.log.warn("VirtualQuery failed on current_base !")
               return 0

           if MemInfo.Type != MEM_PRIVATE or MemInfo.State != MEM_COMMIT:
               self.log.warn("Unexpected memory type encountered !")
               return 0

           current_base = MemInfo.AllocationBase
           r = KERNEL32.ReadProcessMemory(self.process_handle, current_base,
                                            ctypes.byref(Pe_buffer),
                                            self.SIZEOF_PE_BUFFER,
                                            ctypes.byref(BytesToRead))
           if r == 1 and Pe_buffer[0] == 'M' and Pe_buffer[1] == 'Z':
               return current_base
           current_base = current_base - PAGE_SIZE

        return 0
        

            
    def DumpBufferToFile(self, pid, path, base_address, buffer_size):
        ret = 0
    
        hProc = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS,0,self.pid)
        if hProc == INVALID_HANDLE_VALUE:
            raise UnpackerException("OpenProcess failed")
            return 0 
            
        read_buffer = ctypes.create_string_buffer(buffer_size)
        BytesToRead = LONG()
        r = KERNEL32.ReadProcessMemory(hProc, base_address,
                                    ctypes.byref(read_buffer),
                                    buffer_size,
                                    ctypes.byref(BytesToRead))
        if ( r == 1 ):
            f = open(path,"wb")
            f.write(read_buffer)
            f.close()
            ret = 1
        else:
            ret = 0
            
        KERNEL32.CloseHandle(hProc)
        
        return 0
        

    def FindModuleBase(self, Oep):
        oep_in_private_memory = False
        result = 0
        MemInfo = MEMORY_BASIC_INFORMATION()

        r = KERNEL32.VirtualQueryEx(self.process_handle, Oep, ctypes.byref(MemInfo), ctypes.sizeof(MemInfo))
        if r == 0:
            self.log.error("VirtualQuery failed on Oep !")
            return (0, False)

        if MemInfo.State == MEM_FREE:
            self.log.error("Memory at Oep is free !")
            return (0,False)

        if MemInfo.Type == MEM_PRIVATE:
            self.log.info("Oep is in private memory, scanning for valid PE")
            result = self.LocatePeBase(MemInfo.AllocationBase)
            oep_in_private_memory = True

        elif MemInfo.Type == MEM_IMAGE:
            self.log.info("Oep is in an image PE")
            module = self.find_module_by_address(Oep)
            if module != None:
                module_name = "%s" % module.szModule
                self.log.info("OEP is in module %s" % str(module_name))
                if os.path.basename(module_name.lower()) != os.path.basename(self.main_module_name.lower()):
                    self.log.warn("Oep is not in main module")
                    result = 0
                else:
                    result = module.modBaseAddr
            else:
                    self.log.error("Unable to locate the image Oep is in")
                    result = None
        else:
            result = 0

        return (result, oep_in_private_memory)
        
    def DumpPE(self, pid, oep, prog_name):
        (module_base,oep_in_private_memory) = self.FindModuleBase(oep)
        
        r = self.ScyllaDumpProcessA(pid,0,module_base,oep,prog_name)
        if (r == 0):
            return False
        else:
            return True

    def Iat_Rebuild(self, dump_name, unpack_name, Oep):
        result = False
        iat_start = LPVOID(0)
        iat_size = DWORD(0)

        r = self.ScyllaIatSearch(self.pid, 
                                        ctypes.byref(iat_start),
                                        ctypes.byref(iat_size),
                                        DWORD(Oep), 1)
        if r == SCY_ERROR_SUCCESS:
            self.log.info("iat found, address = 0x%x, size = 0x%x" % (iat_start.value,iat_size.value))

            dump_name = dump_name + "\x00"
            unpack_name = unpack_name + "\x00"
             
            r = self.ScyllaIatFixAutoW(iat_start, iat_size, self.pid,
                                                dump_name.encode("utf-16-le"),
                                                unpack_name.encode("utf-16-le"))
            if r == SCY_ERROR_SUCCESS:
                r = self.ScyllaRebuildFileA(unpack_name, 0, 1, 1)
                if r != SCY_ERROR_SUCCESS:
                    result = True
                else:
                    self.log.error("ScyllaRebuildFileA failed !")
            else:
                self.log.error("ScyllaIatFixAutoW failed !")

        return result