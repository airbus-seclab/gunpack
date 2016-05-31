/*
 * Copyright 2016 Julien Lenoir / Airbus Group Innovations
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

#define GPAK_TAG 0x4750414B

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

#define EXCEPTION_BUFFER_SIZE 1024

// Device type
#define SIOCTL_TYPE 40000

// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_SET_PID CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_CLEANUP CTL_CODE( SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_GET_EXCEPTION CTL_CODE( SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_GET_EXCEPTION_COUNT CTL_CODE( SIOCTL_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_SUSPEND_TRACKED CTL_CODE( SIOCTL_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_RETRIEVE_EXCEPTION CTL_CODE( SIOCTL_TYPE, 0x805, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_UNTRACK_AND_RESUME_PROCESSES CTL_CODE( SIOCTL_TYPE, 0x806, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_ADD_TRACKED CTL_CODE( SIOCTL_TYPE, 0x807, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
//#define IOCTL_SET_PAGE_RIGHTS CTL_CODE( SIOCTL_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define RWE_SINGLE_STEP 0
#define RWE_SINGLE_PAGE 1

typedef struct ConfigStruct{
    int debug_log;
    int RWEPolicy;
    int InitiallyNonExecutable;
} ConfigStruct;

typedef struct _PidStruct{
	int debug_log;
    int RWEPolicy;
    int InitiallyNonExecutable;    
	void * UserlandNotidyEvent;
	void * TargetProcessHandle;
} PidStruct;

#endif