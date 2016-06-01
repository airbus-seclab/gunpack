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

from gunpack import *
from log import Log
from generic import Generic
from upack import Upack
from mpress import Mpress
import sys
import logging
import hashlib
import pefile
import argparse
import os

def main():

    parser = argparse.ArgumentParser(description="Gunpack -- Tries to unpack binary ;-)\nWhen the unpacking is successful, Gunpack creates 2 files :\n\t- <filename_of_binary>_<md5_of_binary>_dump.exe : Memory dump of the unpacked binary\n\t- <filename_of_binary>_<md5_of_binary>_unpacked.exe : Real PE of the unpacked binary")
    parser.add_argument("--verbose", "-v", action="count", default=2, help="Increase verbosity")
    parser.add_argument("--file", "-f", dest='binary', type=str, action="store", help=u"Binary file to unpack", required=True)
    parser.add_argument("--output-directory", "-o", "-od", dest='out', type=str, action="store", help=u"Directory where you want to save the unpacked binary. If the option is not set, the unpacked files are saved in the directory of the binary", required=False)
    parser.add_argument("--script", "-s", action="store", help="script to use", dest='script', required=True)
    
    options = parser.parse_args()
    verbosity = max(1,50-10*(options.verbose))
    logging.basicConfig(format="%(levelname)-5s: %(message)s", level=verbosity)
    logobj = logging.getLogger("gunpack")

	#do not close the file here in order to avoid binary removal
    input_file_abs = os.path.abspath(options.binary)
    filename = os.path.basename(input_file_abs)
    
    if options.out is not None:
		out = os.path.abspath(options.out)
		if not(os.path.isdir(out)):
			logobj.error("directory \"%s\" does not exist" % out)
			quit()
    else:
		out = os.path.dirname(input_file_abs)

    device_name = "\\\\.\\MyDevice"

    if ( options.script == "log"):
        unpacker = Log(options.binary)
    elif ( options.script == "upack"):
        unpacker = Upack(options.binary)
    elif ( options.script == "generic"):
        unpacker = Generic(options.binary)
    elif ( options.script == "mpress"):
        unpacker = Mpress(options.binary)          
    else:
        print "Unknown unpacker !"
    
    unpacker.set_params(logobj, device_name, kernel_log = 0, output_directory = out)
    
    unpacker.run(1)

    f.close()

if __name__ == '__main__':
    main()
