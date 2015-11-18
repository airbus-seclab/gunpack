"""
   Copyright 2015 Julien Lenoir / Airbus Group Innovations
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

class PageAccess():
	def __init__(self):
		self.LastWritten = 0
		self.LastExec = 0
		self.ExecAddress = 0
		
	def __str__(self):
		s = ""
		s += "LastWritten : %d " % self.LastWritten
		s += "LastExec : %d " % self.LastExec
		s += "ExecAddress : %x " % self.ExecAddress
		return s

def mutantX(ExceptionsList):

	PageAccessDict = {}
	i = 0
	
	for e in ExceptionsList:
	
		i = i + 1
		PageBase = e.PhysicalAccessedAddress & 0xFFFFF000
		
		if PageBase in PageAccessDict.keys():
			CurrentPage = PageAccessDict[PageBase]
		else:
			CurrentPage = PageAccess()
			PageAccessDict[PageBase] = CurrentPage

		if e.AccessedType == WRITE_ACCESS:
			CurrentPage.LastWritten = i
		elif e.AccessedType == EXECUTE_ACCESS:
			CurrentPage.LastExec = i
			CurrentPage.ExecAddress = e.PhysicalAccessedAddress
		else:
			self.log.error("[AddPageAccess] ERROR : unexpected page access : %d!" % AccessedType)
			raise UnpackerException("unexpected page access" % AccessedType)

	type1_pages = []
	page_access = 0

	for page_base in PageAccessDict.keys():
		page_access = PageAccessDict[page_base]
		if (page_access.LastWritten != 0) and (page_access.LastExec != 0):
			type1_pages.append(page_access)

	last_write = 0
	last_write_page = page_access
	for page_access in type1_pages:
		if page_access.LastWritten > last_write:
			last_write = page_access.LastWritten

	Physical_Oep = 0
	min_exec = 0xFFFFFFFF
	for page_access in type1_pages:
		if (page_access.LastExec > last_write) and (page_access.LastExec < min_exec):
			min_exec = page_access.LastExec
			Physical_Oep = page_access.ExecAddress

	Oep = 0
	if Physical_Oep != 0:
		for exp in ExceptionsList:
			if exp.PhysicalAccessedAddress == Physical_Oep :
				Oep = exp.AccessedAddress

	return (Oep,Physical_Oep)
