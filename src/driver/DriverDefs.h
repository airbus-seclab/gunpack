/*
 * Copyright 2015 Julien Lenoir / Airbus Group Innovations
 * contact: julien.lenoir@airbus.com
 */


/*
 * This file is part of Gunpack.
 *
 * Gunpack is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Gunpack is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Gunpack.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DRIVER_DEFS_H
#define DRIVER_DEFS_H

//Driver stuff
#define DOS_DEVICE_NAME L"\\DosDevices\\MyDevice"
#define DEVICE_NAME L"\\Device\\MYDEVICE"
#define USERLAND_DEVICE_NAME L"\\\\.\\MyDevice"

//#define LEET_MAGIC 0x1337
#define LEET_MAGIC 0x1337
#define LEET_MASK LEET_MAGIC << 16

#define SNAPSHOT_VIRTUAL_VIEW (HANDLE)0xFFFFFFFE
#define GET_VIRTUAL_VIEW (HANDLE)0xFFFFFFFD

#define USERLAND_LIMIT 0x7FFFFFFF

// Device type
#define SIOCTL_TYPE 40000

// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_SET_PID CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_CLEANUP CTL_CODE( SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_GET_EXCEPTION CTL_CODE( SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_GET_EXCEPTION_COUNT CTL_CODE( SIOCTL_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
//#define IOCTL_SET_PAGE_RIGHTS CTL_CODE( SIOCTL_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

typedef struct _PidStruct{
	int do_log;
	unsigned int Pid;
	void * UnpackEvent;
	void * hUnpackEvent;
	void * TargetProcessHandle;
	void * ExpectedEip;
} PidStruct;


typedef struct _MemModifStruct{
	void * hProcess;
	void * address;
	unsigned int execute;
	unsigned int write;
} MemModifStruct;


#endif