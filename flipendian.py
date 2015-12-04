#!/usr/bin/python
import sys
import re
import getopt

def main(argv):
    input_file_name = ''
    output_file_name = ''
    try:
        opts, args = getopt.getopt(argv, "hi:o:",["ifile=", "ofile="])
    except getopt.GetoptError:
        print('flipendian.py -i <file> -o <file>')
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print('flipendian.py -i <file> -o <file>')
            sys.exit(0)
        elif opt in ("-i", "--ifile"):
            input_file_name = arg
        elif opt in ("-o", "--ofile"):
            output_file_name = arg

    if input_file_name == '':
        print('flipendian.py -i <file> -o <file>')
		sys.exit(2)
	if output_file_name == '':
        print('flipendian.py -i <file> -o <file>')
		sys.exit(2)

    input_file = open(input_file_name, 'r', encoding='utf-8')
    output_file = open(output_file_name, 'w', encoding='utf-8')

    flag = True
    while(flag):
        content = input_file.readline()
        if content == '':
            flag = False
        else:
            matches = re.findall(r'[0-9A-Z]+', content)
            outstring = ''
            for match in matches:
                outstring = '\'\\x' + match + '\', ' + outstring
            print(outstring, file=output_file)
    input_file.close()
    output_file.close()

if __name__ == "__main__":
    main(sys.argv[1:])
