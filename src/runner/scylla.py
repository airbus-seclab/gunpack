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