import ctypes
import os
import time
import pefile
try :
    from lib.common.defines import KERNEL32, DWORD, LPVOID, PROCESS_INFORMATION, STARTUPINFO, MEMORY_BASIC_INFORMATION, LONG, BYTE, CREATE_SUSPENDED, MEM_IMAGE, MEM_PRIVATE, MEM_COMMIT, HANDLE, LPTSTR, MODULEENTRY32
except ImportError:
    from defines import KERNEL32, DWORD, LPVOID, PROCESS_INFORMATION, STARTUPINFO, MEMORY_BASIC_INFORMATION, LONG, BYTE, CREATE_SUSPENDED, MEM_IMAGE, MEM_PRIVATE, MEM_COMMIT, HANDLE, LPTSTR, MODULEENTRY32

ONE_SEC = 1000

#############################
#### Windows internal stuff
#############################

LPDWORD = ctypes.POINTER(DWORD)
CHAR = ctypes.c_char
LPSTR = ctypes.POINTER(CHAR)


TH32CS_SNAPMODULE = 0x00000008

PAGE_SIZE = 0x1000
NULL = 0
MEM_FREE = 0x10000

GENERIC_READ  = 	0x80000000
GENERIC_WRITE = 	0x40000000

OPEN_EXISTING = 	3

WAIT_TIMEOUT = 		0x102
WAIT_ABANDONED = 	0x80
WAIT_OBJECT_0 = 	0

PROCESS_ALL_ACCESS = 0x001FFFFF

MAX_PATH = 260
INVALID_HANDLE_VALUE = LPVOID(-1)

#############################
#### Driver communication
#############################


IOCTL_SETUP_STUFF = 		0x9C40E000
IOCTL_CLEANUP = 			0x9C40E004
IOCTL_GET_EXCEPTION = 		0x9C40E008
IOCTL_GET_EXCEPTION_COUNT = 0x9C40E00C

class CatchedException(ctypes.Structure):
    _fields_ = [("AccessedAddress", LPVOID),
				("AccessedType",LONG),
				("InDllLoad",LONG),
				("LockCount",LONG),
				("RecursionCount",LONG),
				("OwningThread",HANDLE),
				("CurrentThread",HANDLE),
				("Physicallow",LONG),
				("Physicalhigh",LONG),
				("Esp",LONG),
				("Esp_top",LONG),
				("DllName",ctypes.c_wchar * MAX_PATH)]

class PID_STRUCT(ctypes.Structure):
    _fields_ = [("do_log", DWORD),
				("Pid", DWORD),
				("UnpackEvent", HANDLE),
				("PipeEvent", HANDLE),
                ("TargetProcessHandle", HANDLE),
				("ExpectedEip", LPVOID)]



#############################
#### Scylla stuff
#############################
SCY_ERROR_SUCCESS = 0

class Scylla:
    def __init__(self, dll_path):
        scylla_dll = ctypes.WinDLL(dll_path)

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
			raise UnpackerException("OpenProcess failed")
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

		return self.modules[name.lower()]
				
	def build_modules_dict(self):
	
		self.modules = {}
		result = None
		hModuleSnap = LPVOID(0)
		me32 = MODULEENTRY32()
		me32.dwSize = ctypes.sizeof(MODULEENTRY32)

		hModuleSnap = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid)
		if hModuleSnap == -1:
			self.log.warn("CreateToolhelp32Snapshot failed")
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
		
		main_module = self.find_module_by_name(self.main_module_name)
		if main_module == None:
			return None
		
		oep = main_module.modBaseAddr + pe.OPTIONAL_HEADER.AddressOfEntryPoint
		
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
                result = self.process.LocatePeBase(MemInfo.AllocationBase)
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
		
		
class UnpackerException(Exception):
   pass 


class Gunpack():

    def __init__(self, log, driver_name, filename, scylla_dll, unpacker, kernel_log):
        self.filename = filename
        self.log = log
        self.process = Process(unpacker.command_line, log)
        self.unpacker = unpacker
        self.kernel_log = kernel_log

        # Open driver device
        self.hdevice = KERNEL32.CreateFileA(driver_name, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
        if self.hdevice == INVALID_HANDLE_VALUE:
            raise WinError()

        self.log.info("Driver device file opened, handle = %d" % self.hdevice)

        # Scylla
        self.scylla = Scylla(scylla_dll)
		
        self.max_unpack_time = 30*ONE_SEC

    def set_unpack_time(self, utime):
        self.max_unpack_time = utime*ONE_SEC

    def Retrieve_Exceptions(self):
        ExceptionsCount = LONG()
        BytesReturned = DWORD()

        #Retrieve exception count
        success = KERNEL32.DeviceIoControl(self.hdevice, IOCTL_GET_EXCEPTION_COUNT,
                                            NULL, 0,
                                            ctypes.byref(ExceptionsCount),
                                            ctypes.sizeof(ExceptionsCount),
                                            ctypes.byref(BytesReturned), 0)
        if not(success):
            self.log.error("DeviceIoControl failed : unable to retrieve exceptions count")
            raise UnpackerException("DeviceIoControl failed : unable to retrieve exceptions count")

        ExceptionsCount = ExceptionsCount.value

        MyCatchedException = CatchedException()

        ExceptionsList = []

        for i in range(ExceptionsCount):
            success = KERNEL32.DeviceIoControl(self.hdevice, IOCTL_GET_EXCEPTION,
                                            NULL, 0,
                                            ctypes.byref(MyCatchedException),
                                            ctypes.sizeof(MyCatchedException),
                                            ctypes.byref(BytesReturned), 0)
            if not(success):
                self.log.error("DeviceIoControl failed : unable to retrieve exception")
                raise UnpackerException("DeviceIoControl failed : unable to retrieve exception")

            AccessedType = MyCatchedException.AccessedType
            AccessedAddress = MyCatchedException.AccessedAddress
            LockCount = MyCatchedException.LockCount
            RecursionCount = MyCatchedException.RecursionCount
            OwningThread = MyCatchedException.OwningThread
            CurrentThread = MyCatchedException.CurrentThread
            Physicallow = MyCatchedException.Physicallow
            Physicalhigh = MyCatchedException.Physicalhigh
            Esp = MyCatchedException.Esp
            Esp_top = MyCatchedException.Esp_top
            DllName = MyCatchedException.DllName
			
            if self.unpacker.filter_execption(self.process,MyCatchedException):
			
				NewException = CatchedException()
				NewException.AccessedType = AccessedType
				NewException.AccessedAddress = AccessedAddress
				NewException.LockCount = LockCount
				NewException.RecursionCount = RecursionCount
				NewException.OwningThread = OwningThread
				NewException.CurrentThread = CurrentThread
				NewException.Physicallow = Physicallow
				NewException.Physicalhigh = Physicalhigh
				NewException.Esp = Esp
				NewException.Esp_top = Esp_top	
				NewException.PhysicalAccessedAddress = Physicalhigh * 0x100000000 + Physicallow
				NewException.DllName = DllName
				
				ExceptionsList.append(NewException)

        self.unpacker.set_exeptions_list(ExceptionsList)

    def Iat_Rebuild(self, dump_name, unpack_name, Oep):
        result = False
        iat_start = LPVOID(0)
        iat_size = DWORD(0)

        r = self.scylla.ScyllaIatSearch(self.process.pid, 
                                        ctypes.byref(iat_start),
                                        ctypes.byref(iat_size),
                                        DWORD(Oep), 1)
        if r == SCY_ERROR_SUCCESS:
            self.log.info("iat found, address = 0x%x, size = 0x%x" % (iat_start.value,iat_size.value))

            r = self.scylla.ScyllaIatFixAutoW(iat_start, iat_size, self.process.pid,
                                                dump_name.encode("utf-16-le"),
                                                unpack_name.encode("utf-16-le"))
            if r == SCY_ERROR_SUCCESS:
                r = self.scylla.ScyllaRebuildFileA(unpack_name, 0, 1, 1)
                if r != SCY_ERROR_SUCCESS:
                    result = True
                else:
                    self.log.error("ScyllaRebuildFileA failed !")
            else:
                self.log.error("ScyllaIatFixAutoW failed !")

        return result

    def UnpackOnce(self, PreviousOep):
		oep_in_private_memory = False

		#Start target process in suspended state
		self.process.create_suspended()

		self.log.info("Target process handle value is 0x%x" % self.process.process_handle)

		#Create an unpack event which will be signaled when the
		hUnpackEvent = KERNEL32.CreateEventA(NULL,0,0,"DaEvent")

		#Struct sent to the driver, PreviousOep can be NULL
		MyPidStruct = PID_STRUCT(self.kernel_log,self.process.pid,NULL,hUnpackEvent,self.process.process_handle,PreviousOep)

		#Initiate driver's sta  te and communication mecanisms
		BytesReturned = DWORD(0)
		success = KERNEL32.DeviceIoControl(self.hdevice,IOCTL_SETUP_STUFF,ctypes.byref(MyPidStruct),ctypes.sizeof(MyPidStruct),NULL,0,ctypes.byref(BytesReturned),0)
		if not(success):
				self.log.error("DeviceIoControl failed")
				raise UnpackerException("DeviceIoControl failed")

		#Resume main process thtread
		self.process.resume()
		self.log.info("Main thread resumed")

		#Wait for unpacking to terminate
		r = KERNEL32.WaitForSingleObject(hUnpackEvent,self.max_unpack_time)
		if (r == WAIT_ABANDONED ):
				self.log.error("Wait abandoned, something went wrong")
				raise UnpackerException("Wait abandoned, something went wrong")
		if (r == WAIT_TIMEOUT):
				self.log.info("Wait timed out")
				self.process.suspend()
				self.log.info("Thread suspended")

		if (r == WAIT_OBJECT_0):
				self.log.info("Event signaled")
		
		#Retrieve all exceptions logger by our driver
		self.Retrieve_Exceptions()

		success = KERNEL32.DeviceIoControl(self.hdevice,IOCTL_CLEANUP,NULL,0,NULL,0,ctypes.byref(BytesReturned),0)
		if not(success):
				self.log.error("DeviceIoControl failed : unable to process to cleanup")

		if ( PreviousOep == NULL ):
				#We are on the first run, we compute the Oep
				#Apply algorithm to figure out Oep
				Oep = self.unpacker.find_oep(self.process)
				if( Oep == 0 ):
					self.log.error("Oep not found !")
					return (0,False)
				else:
					self.log.info("Found OEP at 0x%x" % Oep)
		else:
				#We are on the second run, we need to ensure that the last Exception is on the expected Oep
				#If last exception is not our expected Oep this means that something went wrong
				if ( self.unpacker.last_execption_address().AccessedAddress != PreviousOep ):
					self.log.error("Unexpected Oep on second run")
					return (0, False)
				else:
					Oep = PreviousOep

		success = KERNEL32.DeviceIoControl(self.hdevice,IOCTL_CLEANUP,NULL,0,NULL,0,ctypes.byref(BytesReturned),0)
		if not(success):
				self.log.error("DeviceIoControl failed : unable to process tp cleanup")

		if ( Oep == 0 ):
				KERNEL32.TerminateProcess(self.hProcess,0)
				self.log.error("Error OEP not found !")
				raise UnpackerException("OEP Not found !")
		else:
				(module_base,oep_in_private_memory) = self.process.FindModuleBase(Oep)

		if ( module_base == 0 ):
				self.log.error("Unable to figure out module base !")
				raise UnpackerException("Unable to figure out module base !")

		self.log.info("Module base at : 0x%x" % module_base)

		if ( ((PreviousOep == NULL) and (oep_in_private_memory)) or ( (PreviousOep != NULL) and not(oep_in_private_memory) ) ):
				
				r = self.scylla.ScyllaDumpProcessA(self.process.pid,NULL,module_base,Oep,self.unpacker.get_dump_name())
				if (r == 0):
					self.log.error("Error : unable to dump target process")
					raise UnpackerException("Unable to dump target")
				else:
					self.log.info("Target process dumped with oep : 0x%x" % Oep)

				if self.Iat_Rebuild(self.unpacker.get_dump_name()+"\x00",self.unpacker.get_unpack_name()+"\x00", Oep):
					self.log.info("Iat rebuilt successfully")
				else:
					self.log.error("Unable to rebuild Iat")

		self.process.terminate()
		self.log.info("Process terminated")

		KERNEL32.CloseHandle(hUnpackEvent)

		return (Oep,oep_in_private_memory)

    def clean(self):
        KERNEL32.CloseHandle(self.hdevice)
