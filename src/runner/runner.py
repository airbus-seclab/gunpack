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

from gunpack import Gunpack
from exeunpack import ExeUnpacker
from dllunpacker import DllUnpacker
import sys
import logging
import hashlib
import pefile
import argparse
import os

IMAGE_FILE_DLL = 0x2000
IMAGE_FILE_EXECUTABLE_IMAGE = 0x2

def main():

    parser = argparse.ArgumentParser(description="Gunpack -- Tries to unpack binary ;-)\nWhen the unpacking is successful, Gunpack creates 2 files :\n\t- <filename_of_binary>_<md5_of_binary>_dump.exe : Memory dump of the unpacked binary\n\t- <filename_of_binary>_<md5_of_binary>_unpacked.exe : Real PE of the unpacked binary")
    parser.add_argument("--verbose", "-v", action="count", default=2, help="Increase verbosity")
    parser.add_argument("--file", "-f", dest='binary', type=str, action="store", help=u"Binary file to unpack", required=True)
    parser.add_argument("--output-directory", "-out-d", "-od", dest='out', type=str, action="store", help=u"Directory where you want to save the unpacked binary. If the option is not set, the unpacked files are saved in the directory of the binary", required=False)

    options = parser.parse_args()
    verbosity = max(1,50-10*(options.verbose))
    logging.basicConfig(format="%(levelname)-5s: %(message)s", level=verbosity)
    log = logging.getLogger("gunpack")

    # Compute the md5
    f = open(options.binary, 'rb')
    md5 = hashlib.md5(f.read()).hexdigest()
	
	#do not close the file here in order to avoid binary removal


    input_file_abs = os.path.abspath(options.binary)
    filename = os.path.basename(input_file_abs)
    
    if options.out is not None:
		out = os.path.abspath(options.out)
		if not(os.path.isdir(out)):
			log.error("directory \"%s\" does not exist" % out)
			quit()
    else:
		out = os.path.dirname(input_file_abs)

    device_name = "\\\\.\\MyDevice"

    try:
        pe = pefile.PE(options.binary)
    except pefile.PEFormatError as e:
        log.error("PE format error for %s" % filename)
        quit()
    except Exception, e:
        print log.error("unknown error")
        print e
        quit()

    if ( pe.FILE_HEADER.Characteristics & IMAGE_FILE_DLL ):
        log.info("Input file is a Dll")
        dump_name = "%s\\%s_%s_dump.dll" % (out, filename, md5)
        unpacked_name = "%s\\%s_%s_unpacked.dll" % (out, filename, md5)
        command_line = "python load_dll.py %s" % input_file_abs

        unpacker = DllUnpacker(command_line, dump_name, unpacked_name, input_file_abs)

    elif ( pe.FILE_HEADER.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE ):
        log.info("Input file is an Exe")
        dump_name = "%s\\%s_%s_dump.exe" % (out, filename, md5)
        unpacked_name = "%s\\%s_%s_unpacked.exe" % (out, filename, md5)
        unpacker = ExeUnpacker(input_file_abs, dump_name, unpacked_name, input_file_abs)
    else:
        print log.error("Unsupported pe type")
        quit()

    unpacker = Gunpack(log, device_name, options.binary, "Scylla_x86.dll", unpacker, kernel_log = 0)

    (Oep, oep_in_private_memory) = unpacker.UnpackOnce(0)
    if (Oep == 0):
            log.error("Unable to find Oep")
            quit()

    if ( not(oep_in_private_memory) ):
            unpacker.UnpackOnce(Oep)
			
    f.close()

if __name__ == '__main__':
    main()
