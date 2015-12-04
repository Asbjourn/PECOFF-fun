#!/usr/bin/python
import sys
import re
import getopt
import struct

def main(argv):
    input_file_name = ''
    shift_string = ''
    try:
        opts, args = getopt.getopt(argv, "hi:s:",["ifile=", "shift="])
    except getopt.GetoptError:
        print('shiftsections.py -i <file> -s <int>')
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print('shiftsections.py -i <file> -s <int>')
            print('This script shifts the section headers file pointers by the indicated amount')
            print('It does not perform the byte shift itself, only updates the pecoff headers')
            print('This (currently) assumes a properly formed PE32 header')
            print('Do not run this more than once, remember to recalculate the PE checksum')
            sys.exit(0)
            
        elif opt in ("-i", "--ifile"):
            input_file_name = arg
        elif opt in ("-s", "--shift"):
            shift_string = arg

    if input_file_name == '':
        print('shiftsections.py -i <file> -s <int>')
        sys.exit(2)
    if shift_string == '':
        print('shiftsections.py -i <file> -s <int>')
        sys.exit(2)

    shift = int(shift_string)
    with open(input_file_name, 'r+b') as f:
        f.seek(0x3C, 0)
        data = f.read(4)
        pe = struct.unpack("<L", data)[0]
        print("PE Header location: {0}".format(pe))
        f.seek(pe + 0x06, 0)
        data = f.read(2)
        num_sects = struct.unpack("<H", data)[0]
        print("Number of sections: {0}".format(num_sects))
        section_header = pe + 0xf8;
        print("Section header location: {0}".format(section_header))
        for i in range(0, num_sects):
            f.seek(section_header + 0x28*i, 0)
            title = f.read(8)
            f.seek(section_header + 0x28*i + 0x14, 0)
            data = f.read(4)
            old_pointer = struct.unpack("<L", data)[0]
            new_pointer = 0;
            if old_pointer != 0:
                new_pointer = old_pointer + shift
            print("{0}: {1}\t->\t{2}".format(title, old_pointer, new_pointer))
            data = struct.pack("<L", new_pointer)
            f.seek(section_header + 0x28*i + 0x14, 0)
            f.write(data)
            
        
if __name__ == "__main__":
    # NOTE!!! THIS WAS WRITTEN FOR PE32 WINDOWS PECOFFS
    # THIS ALSO ASSUMES YOU HAVE ALREADY UPDATED PE HEADER LOCATION
    # DO NOT RUN THIS MORE THAN ONCE
    main(sys.argv[1:])
