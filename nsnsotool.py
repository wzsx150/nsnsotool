# ported from https://github.com/0CBH0/nsnsotool
# Nso Header from https://github.com/Atmosphere-NX/Atmosphere/blob/35d93a7c4188cda103957aa757fd31f9fe7d18cb/libraries/libstratosphere/include/stratosphere/ldr/ldr_types.hpp#L84

import sys
import os
import argparse
import struct
import shutil
import hashlib
from copy import deepcopy
import pprint

import lz4.block


class NSOfile:
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.Compressed = False
        
        # 0x100 bytes
        self.nso_header_fmt = '<4s15I32s3I28s6I32s32s32s'
        self.BID = ''
        self.header_info = {
        
        # Each is 4 bytes
        'magic' : b'',
        'version' : 0x0,
        'pad_a' : 0x0,
        'flags' : 0x0,
        
        # Each is 4 bytes
        'text_fileOffset' : 0x0,
        'text_memoryOffset' : 0x0,
        'text_dcmpSize' : 0x0,
        'modOffset' : 0x0,
        
        # Each is 4 bytes
        'rodata_fileOffset' : 0x0,
        'rodata_memoryOffset' : 0x0,
        'rodata_dcmpSize' : 0x0,
        'modSize' : 0x0,
        
        # Each is 4 bytes
        'rwdata_fileOffset' : 0x0,
        'rwdata_memoryOffset' : 0x0,
        'rwdata_dcmpSize' : 0x0,
        'bssSize' : 0x0,
        
        
        'note' : b'',  # 32 bytes
        'text_cmpSize' : 0x0,  # 4 bytes
        'rodata_cmpSize' : 0x0,  # 4 bytes
        'rwdata_cmpSize' : 0x0,  # 4 bytes
        'pad_b' : b'',  # 28 bytes
        
        # Each is 4 bytes
        'rdOffset_api' : 0x0,
        'rdSize_api' : 0x0,
        'rdOffset_dynstr' : 0x0,
        'rdSize_dynstr' : 0x0,
        'rdOffset_dynsym' : 0x0,
        'rdSize_dynsym' : 0x0,
        
        # Each is 32 bytes
        'text_sha256_hash' : b'',
        'rodata_sha256_hash' : b'',
        'rwdata_sha256_hash' : b''
        
        }

        # raw bytes
        self.NSORaw = bytearray()
        self.header = bytearray()
        self.mod = bytearray()
        
        # raw bytes
        self.text_dcmp = bytearray()
        self.text_dcmp = bytearray()
        self.text_dcmp = bytearray()
        
        # compressed bytes
        self.text_cmp = bytearray()
        self.rodata_cmp = bytearray()
        self.rwdata_cmp = bytearray()

        self.get_struct_from_file()


    def is_NSO_file(self):
        if not self.check_file_exist(self.file_path):
            return False

        buf = bytearray(4)
        with open(self.file_path, 'rb') as fp:
            fp.readinto(buf)
        self.Magic = buf.decode('unicode_escape')
        return self.Magic == 'NSO0'

    def get_struct_from_file(self):
        if not self.is_NSO_file():
            raise ValueError('Error parsing the file, it may not be a valid NSO file.')
        
        buf = bytearray(os.path.getsize(self.file_path))
        with open(self.file_path, 'rb') as fp:
            fp.readinto(buf)
        self.NSORaw = buf
        unpacked_data = struct.unpack(self.nso_header_fmt, buf[:0x100])
        self.header_info = dict(zip(self.header_info.keys(), unpacked_data))
        self.BID = ''.join(f'{byte:02X}' for byte in self.header_info['note'][:8])
        print(f'BID: {self.BID}')
        self.pprint_header_info()
        
        if (self.header_info['flags'] & 0b111):
            self.Compressed = True 

    def pprint_header_info(self):
        hex_header_info = {k: (f'0x{v:X}' if isinstance(v, int) else v) for k, v in self.header_info.items()}
        pprint.pprint(hex_header_info, sort_dicts=False)

    def process_file(self):
        self.header = self.NSORaw[:self.header_info['flags']]
        self.mod = self.NSORaw[self.header_info['modOffset']:self.header_info['modSize']]
        if self.Compressed:
            self.text_cmp = self.NSORaw[self.header_info['text_fileOffset']:self.header_info['text_fileOffset'] + self.header_info['text_cmpSize']]
            self.rodata_cmp = self.NSORaw[self.header_info['rodata_fileOffset']:self.header_info['rodata_fileOffset'] + self.header_info['rodata_cmpSize']]
            self.rwdata_cmp = self.NSORaw[self.header_info['rwdata_fileOffset']:self.header_info['rwdata_fileOffset'] + self.header_info['rwdata_cmpSize']]
        else:
            self.text_dcmp = self.NSORaw[self.header_info['text_fileOffset']:self.header_info['text_fileOffset'] + self.header_info['text_dcmpSize']]
            self.rodata_dcmp = self.NSORaw[self.header_info['rodata_fileOffset']:self.header_info['rodata_fileOffset'] + self.header_info['rodata_dcmpSize']]
            self.rwdata_dcmp = self.NSORaw[self.header_info['rwdata_fileOffset']:self.header_info['rwdata_fileOffset'] + self.header_info['rwdata_dcmpSize']]

    def is_Compressed(self):
        return self.Compressed

    def check_file_exist(self, file_path: str):
        if not os.path.isfile(file_path):
            raise ValueError(f'Unable to find the file: {file_path}')
        return True

    def generate_tmp_path(self, input_path: str):
        dir_name, file_name = os.path.split(input_path)
        new_file_name = f'{file_name}_nso_temp.bin'
        output_path = os.path.join(dir_name, new_file_name)
        return output_path

    def generate_dec_path(self, input_path: str):
        dir_name, file_name = os.path.split(input_path)
        new_file_name = f'{file_name}_nso_decompressed.bin'
        output_path = os.path.join(dir_name, new_file_name)
        return output_path

    def generate_com_path(self, input_path: str):
        dir_name, file_name = os.path.split(input_path)
        new_file_name = f'{file_name}_nso_compressed.bin'
        output_path = os.path.join(dir_name, new_file_name)
        return output_path


    def decompress(self, out_path: str):
        out_file = open(out_path, 'wb')
        
        if not self.Compressed:
            out_file.write(self.NSORaw)
            out_file.close()
            return
        
        out_file_header_info = deepcopy(self.header_info)
        out_file_header_info['flags'] = 0x0
        out_file_header_info['text_sha256_hash'] = b''
        out_file_header_info['rodata_sha256_hash'] = b''
        out_file_header_info['rwdata_sha256_hash'] = b''

        # out_file_header_info['text_fileOffset'] = out_file_header_info['modOffset'] + out_file_header_info['modSize']
        out_file_header_info['rodata_fileOffset'] = out_file_header_info['text_fileOffset'] + out_file_header_info['text_dcmpSize']
        out_file_header_info['rwdata_fileOffset'] = out_file_header_info['rodata_fileOffset'] + out_file_header_info['rodata_dcmpSize']
        
        out_file_header_info['text_cmpSize'] = self.header_info['text_dcmpSize']
        out_file_header_info['rodata_cmpSize'] = self.header_info['rodata_dcmpSize']
        out_file_header_info['rwdata_cmpSize'] = self.header_info['rwdata_dcmpSize']
        
        packed_data_tmp = struct.pack(self.nso_header_fmt, *out_file_header_info.values())
        out_file.write(packed_data_tmp)  # header
        out_file.write(bytes(self.header_info['modSize']))  # mod
        
        dcmpData = lz4.block.decompress(self.text_cmp, uncompressed_size=self.header_info['text_dcmpSize'])
        out_file.write(dcmpData)  # text
        
        dcmpData = lz4.block.decompress(self.rodata_cmp, uncompressed_size=self.header_info['rodata_dcmpSize'])
        out_file.write(dcmpData)  # rodata
        
        dcmpData = lz4.block.decompress(self.rwdata_cmp, uncompressed_size=self.header_info['rwdata_dcmpSize'])
        out_file.write(dcmpData)  # rwdata
        
        out_file.close()
        NSOfile(out_path)
        print("====== Decompression completed ======")

    def self_decompress(self):
        if not self.Compressed:
            print("====== Decompression completed ======")
            return
        
        out_path = self.file_path
        tmp_path = self.generate_tmp_path(self.file_path)

        self.decompress(tmp_path)
        os.remove(out_path)

        shutil.copyfile(tmp_path, out_path)
        os.remove(tmp_path)

    def compress(self, out_path: str):
        out_file = open(out_path, 'wb')
        
        if self.Compressed:
            out_file.write(self.NSORaw)
            out_file.close()
            return
        
        out_file.write(bytes(0x100))  # empty header
        out_file.write(bytes(self.header_info['modSize']))  # mod
        out_file_header_info = deepcopy(self.header_info)
        out_file_header_info['flags'] = 0x3F
        out_file_header_info['text_sha256_hash'] = hashlib.sha256(self.text_dcmp).digest()
        out_file_header_info['rodata_sha256_hash'] = hashlib.sha256(self.rodata_dcmp).digest()
        out_file_header_info['rwdata_sha256_hash'] = hashlib.sha256(self.rwdata_dcmp).digest()

        text_cmpData = lz4.block.compress(self.text_dcmp, store_size=False)
        out_file.write(text_cmpData)  # text
        out_file_header_info['text_cmpSize'] = len(text_cmpData)
        out_file_header_info['rodata_fileOffset'] = out_file_header_info['text_fileOffset'] + out_file_header_info['text_cmpSize']
        
        rodata_cmpData = lz4.block.compress(self.rodata_dcmp, store_size=False)
        out_file.write(rodata_cmpData)  # rodata
        out_file_header_info['rodata_cmpSize'] = len(rodata_cmpData)
        out_file_header_info['rwdata_fileOffset'] = out_file_header_info['rodata_fileOffset'] + out_file_header_info['rodata_cmpSize']

        rwdata_cmpData = lz4.block.compress(self.rwdata_dcmp, store_size=False)
        out_file.write(rwdata_cmpData)  # rwdata
        out_file_header_info['rwdata_cmpSize'] = len(rwdata_cmpData)
        
        out_file.seek(0)
        packed_data_tmp = struct.pack(self.nso_header_fmt, *out_file_header_info.values())
        out_file.write(packed_data_tmp)  # real header

        out_file.close()
        NSOfile(out_path)
        print("====== Compression completed ======")

    def self_compress(self):
        if self.Compressed:
            print("====== Compression completed ======")
            return
        
        out_path = self.file_path
        tmp_path = self.generate_tmp_path(self.file_path)

        self.compress(tmp_path)
        os.remove(out_path)

        shutil.copyfile(tmp_path, out_path)
        os.remove(tmp_path)


def main():
    overwrite = False
    parser = argparse.ArgumentParser(description='Compress or decompress NSO/NRO files for Nintendo Switch.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-c', '--compress', action='store_true', help='Compress NSO/NRO file')
    group.add_argument('-d', '--decompress', action='store_true', help='Decompress NSO/NRO files')
    parser.add_argument('input_file', type=str, help='Input file path')
    parser.add_argument('output_file', type=str, nargs='?', help='Output file path (optional, if not provided, overwrite the input file)')
    args = parser.parse_args()

    if args.output_file is None:
        overwrite = True
        args.output_file = args.input_file

    if args.compress:
        print(f'Compressing file: {args.input_file} to {args.output_file}\n')
        inputnsofile = NSOfile(args.input_file)
        inputnsofile.process_file()
        if overwrite:
            inputnsofile.self_compress()
        else:
            inputnsofile.compress(args.output_file)
    elif args.decompress:
        print(f'Decompressing file: {args.input_file} to {args.output_file}\n')
        inputnsofile = NSOfile(args.input_file)
        inputnsofile.process_file()
        if overwrite:
            inputnsofile.self_decompress()
        else:
            inputnsofile.decompress(args.output_file)

if __name__ == '__main__':
    main()






