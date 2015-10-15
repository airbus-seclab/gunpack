import ctypes
import sys

if len(sys.argv) == 2:

	dll_path = sys.argv[1]
	
	print dll_path
	#load dll
	loaded_dll = ctypes.WinDLL(dll_path)
