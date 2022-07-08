from binascii import hexlify, unhexlify
import pefile
import argparse
import logging
import traceback
import os
import regex as re
from arc4 import ARC4

def configure_logger(log_level):
    log_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'cruloader_png_payload_extractor.log')
    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(log_level, 0), 3) #clamp to 0-3 inclusive
    logging.basicConfig(level=log_levels[log_level], 
                        format='%(asctime)s - %(name)s - %(levelname)-8s %(message)s',
                        handlers=[
                            logging.FileHandler(log_file, 'a'),
                            logging.StreamHandler()
                        ])

class Unpacker:
    
    def __init__(self, input_file, output_file=None):
        self.logger = logging.getLogger('CruLoader Unpacker')
        self.input_file = input_file
        self.output_file = output_file
        self.unpacked = None
        self.payload_marker = bytes('redaolurc', encoding='utf-8')
        with open(self.input_file, 'rb') as fp:
            self.data = fp.read()
            self.data = self.data.split(self.payload_marker)[1]

    def unpack(self):
        """
        Extract Payload Stored after Marker redaolurc.
        """
        # Decrypt the payload
        self.unpacked = self.xor_decrypt(bytes('a', 'utf-8'), self.data)

    def xor_decrypt(self, key, data):
        """
        XOR Decrypt payload using key and ciphertext. Return decrypted file.
        """
        buf = bytearray(data)
        for i in range(len(buf)):
            buf[i] ^= key[i%len(key)]
        return buf


    def write_output(self):
        """
        Write output to a given file
        """
        try:
            with open(self.output_file, 'wb') as fp:
                fp.write(self.unpacked)
                self.logger.debug(f'Unpacked file written to {self.output_file}')
        except Exception as e:
            self.logger.debug(traceback.format_exc())
        self.logger.critical(f'[*] Payload written to {self.output_file}')            

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Cruloader PNG Payload Extractor')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        required=True, help='Path of file to unpack')
    parser.add_argument('-o', '--outfile', action='store', dest='outfile',
                        required=True, help='Path to write unpacked file')
    parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    args = parser.parse_args()
    configure_logger(args.verbose)
    unpacker = Unpacker(args.file, args.outfile)
    try:
        unpacker.unpack()
        unpacker.write_output()
    except Exception as e:
        print(f'Exception processing {args.file}:')
        print(traceback.format_exc())
    
