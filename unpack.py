from binascii import hexlify, unhexlify
import pefile
import argparse
import logging
import traceback
import os
import regex as re
from arc4 import ARC4

def configure_logger(log_level):
    log_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'cruloader_unpack.log')
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
        self.regex = re.compile(rb'(\xB8|\xB9|\xBA|\xBB|\xBD|\xBE|\xBF)(?P<ct_addr>...)\x00[^\xE8]{0,16}\xE8', re.DOTALL)
        self.pe = pefile.PE(self.input_file)
        self.unpacked = None
        with open(self.input_file, 'rb') as fp:
            self.data = fp.read()

    def unpack(self):
        """
        Extract key and data stored in RCData. 
        """
        for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if str(entry.name) == 'RC_DATA' or 'RCDATA':
                for res in entry.directory.entries:
                    data_rva = res.directory.entries[0].data.struct.OffsetToData
                    size = res.directory.entries[0].data.struct.Size
                    data = self.pe.get_memory_mapped_image()[data_rva:data_rva+size]
        
        # Key is 16 bytes starting at pos 12
        key = data[12:27]
        self.logger.critical(f'[*] Key is: {hexlify(key)}')
        # CT begins after key
        ciphertext = data[28:]
        
        # Unpack the payload
        self.unpacked = self.rc4_decrypt(key, ciphertext)

    def rc4_decrypt(self, key, data):
        """
        RC4 Decrypt payload using key and ciphertext. Return decrypted file.
        """
        self.logger.critical(f'[*] Unpacking payload')
        cipher = ARC4(key)
        decrypted = cipher.decrypt(data)
        return decrypted

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
                ciphertext = fp.read(20)
                ciphertext = ciphertext.split(b'\x00')[0]
                self.logger.debug(f'Found ciphertext: {hexlify(ciphertext)}')
        except Exception as e:
            self.logger.debug('Could not find ciphertext for {ct_ptr}')
            return

        return ciphertext

    def decrypt_strings(self): 
        # Extract alphabet
        custom_dict = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./='     

        # Extract Encrypted Strings
        ct_libs = []
        matches = list(self.regex.finditer(self.data))
        for ct in matches:
            if not ct.group('ct_addr'):
                self.logger.warning(f'No ciphertext: {match.groupdict()}')
                continue
            ciphertext_ptr = bytes(reversed(ct.group('ct_addr')))
            ciphertext = self.dereference_ct_ptr(ciphertext_ptr)
            try:
                ct_libs.append(ciphertext.decode("utf-8"))
            except Exception as e:
                self.logger.debug(f'Could not decode to ascii: {ciphertext}. Likely not valid ciphertext.')
        ct_libs = set(ct_libs)
        for ct in ct_libs:
            decrypted_lib = ""
            for char in ct:
                pos = custom_dict.find(char)
                decrypted_lib += custom_dict[(pos+13)%len(custom_dict)]
            if len(decrypted_lib) > 1:
                self.logger.critical(f'[*] Encrypted: {ct} --> Decrypted: {decrypted_lib}')

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
    parser = argparse.ArgumentParser(description='Cruloader Stage 1 Unpacker')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        required=True, help='Path of file to unpack')
    parser.add_argument('-o', '--outfile', action='store', dest='outfile',
                        required=False, help='Path to write unpacked file')
    parser.add_argument('-d', '--decrypt', action='store_true', default=False,
            required=False, help='Decrypt encrypted strings')
    parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    args = parser.parse_args()
    configure_logger(args.verbose)
    unpacker = Unpacker(args.file, args.outfile)
    try:
        unpacker.unpack()
        if args.outfile:
            unpacker.write_output()
        if args.decrypt:
            unpacker.decrypt_strings()
    except Exception as e:
        print(f'Exception processing {args.file}:')
        print(traceback.format_exc())
    
