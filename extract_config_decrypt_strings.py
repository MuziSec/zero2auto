from binascii import hexlify, unhexlify
import pefile
import argparse
import logging
import traceback
import os
import regex as re

def configure_logger(log_level):
    log_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'cruloader_str_decryptor.log')
    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(log_level, 0), 3) #clamp to 0-3 inclusive
    logging.basicConfig(level=log_levels[log_level], 
                        format='%(asctime)s - %(name)s - %(levelname)-8s %(message)s',
                        handlers=[
                            logging.FileHandler(log_file, 'a'),
                            logging.StreamHandler()
                        ])

class Decryptor:
    
    def __init__(self, input_file, output_file=None):
        self.logger = logging.getLogger('CruLoader String Decrypt and Config Extractor')
        self.input_file = input_file
        self.output_file = output_file
        self.str_regex = re.compile(rb'\x0F.{2}(?P<ct_addr>....).{0,40}\x0F.\x45.\xFF\x15.{4}\x33.{1,4}\x8A.{3}\xC0(\xC1|\xC2)\x04\x80.(?P<xor_key>.)', re.DOTALL)
        self.pe = pefile.PE(self.input_file)
        self.unpacked = None
        with open(self.input_file, 'rb') as fp:
            self.data = fp.read()
        self.output_strings = []
        self.config_url = []

    def dereference_ct_ptr(self, ciphertext_ptr):
        """
        Dereference ciphertext ptr and return ciphertext
        """
        ciphertext_ptr = int.from_bytes(ciphertext_ptr, "big")

        try:
            # Extract Ciphertext Addr
            ct_ptr = self.pe.get_offset_from_rva(ciphertext_ptr - self.pe.OPTIONAL_HEADER.ImageBase)
            self.logger.debug(f'Found potential ciphertext ptr at {hex(ct_ptr)}')
        except Exception as e:
            self.logger.debug(f'CT Address Invalid PTR at {hex(ciphertext_ptr)}')

        # Extract Ciphertext from PTR
        try:
            with open(self.input_file, 'rb') as fp:
                fp.seek(ct_ptr, 0)
                ciphertext = fp.read(50)
                ciphertext = ciphertext.split(b'\x00')[0]
                self.logger.debug(f'Found ciphertext: {hexlify(ciphertext)}')
        except Exception as e:
            self.logger.debug('Could not find ciphertext for {ct_ptr}')
            return

        return ciphertext

    def rol(self, buf, shift):
        output = bytearray(len(buf))
        for i in range(0,len(buf)):
            output[i] = ((buf[i] << shift%8) & 0xFF) | buf[i] >> (8-(shift%8))
        return output

    def decrypt(self, ciphertext, xor_key):
        self.logger.debug((f'Ciphertext: {ciphertext}'))
        self.logger.debug((f'XOR Key: {xor_key}'))

        # ROL 4, XOR Decrypt
        buf = bytearray(ciphertext)
        buf = self.rol(buf, 0x4) 
        key = bytearray(xor_key)
        for i in range(len(buf)):
            buf[i] ^= key[i%len(key)]
        try:
            if buf.decode('ascii').startswith('http'):
                self.config_url.append(buf.decode('ascii'))
            else:
                self.output_strings.append(buf.decode('ascii'))
        except:
            if buf.decode('ascii').startswith('http'):
                self.config_url.append(buf.decode('ascii'))
            else:
                self.output_strings.append(buf)

    def decrypt_strings(self): 

        # Extract Encrypted Strings
        matches = list(self.str_regex.finditer(self.data))
        # print(matches)
        for ct in matches:
            if not ct.group('ct_addr'):
                self.logger.warning(f'No ciphertext: {match.groupdict()}')
                continue
            ciphertext_ptr = bytes(reversed(ct.group('ct_addr')))
            ciphertext = self.dereference_ct_ptr(ciphertext_ptr)
            self.decrypt(ciphertext, ct.group('xor_key'))
        print(f'[*] Config URL(s): {self.config_url}')
        print(f'[*] Decrypted strings: {self.output_strings}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Cruloader Stage 2 String Decryptor and Config Extractor')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        required=True, help='Path of file to unpack')
    parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    args = parser.parse_args()
    configure_logger(args.verbose)
    decryptor = Decryptor(args.file)
    try:
        decryptor.decrypt_strings()
    except Exception as e:
        print(f'Exception processing {args.file}:')
        print(traceback.format_exc())
    
