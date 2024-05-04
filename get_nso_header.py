#!/usr/bin/env python3
# coding=utf-8

import os
import sys
import struct


# 对 switch 游戏nsp/xci文件解包后，再进一步解包nca文件，最后得到的main文件就是NSO文件，也就是游戏程序的主程序。
# 这个脚本可以解析main文件的文件头，得到一些程序加载的信息。


# NSO Header的格式定义
nso_header_format = '<4s15I8s24xIII52sIII32s32s32s'
# 计算头部大小
header_size = struct.calcsize(nso_header_format)

# 定义NSO头部字段名称
header_fields = [
    'magic', 'version', 'reserved_08', 'flags',
    'text_file_offset', 'text_memory_offset', 'text_size',
    'module_offset', 'ro_file_offset', 'ro_memory_offset', 'ro_size', 'module_file_size',
    'rw_file_offset', 'rw_memory_offset', 'rw_size',  # data 段
    'bss_size',  # bss 段
    'module_id',   # 从 17*4 开始，实际 0x20 长度，通常取前 8 个字节的十六进制ASCII码作为 BID
    'text_compressed_size', 'ro_compressed_size', 'rw_compressed_size',
    'reserved_6C', 'text_hash', 'ro_hash', 'rw_hash'
]

# 读取NSO文件头
def read_nso_header(filename):
    with open(filename, 'rb') as f:
        header_data = f.read(header_size)
        if len(header_data) != header_size:
            raise ValueError("Incomplete NSO header")

        unpacked_data = struct.unpack(nso_header_format, header_data)

        # 输出字段的值和十六进制表示
        for name, value in zip(header_fields, unpacked_data):
            if name == 'magic':
                print(f"{name}: {value.decode()} ({value.hex()})")
                continue
            elif name == 'module_id':
                print(f"{name}: {value.hex().upper()}")
                continue
            if isinstance(value, int):
                print(f"{name}: {value} (0x{value:X})")
            else:
                print(f"{name}: {value.hex()}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: \n\tpython get_nso_header.py <path_to_file>")
        print("\nPlease provide the nso file path as an argument.\n")
        sys.exit(1)  # 退出代码1表示发生了错误

    nso_file_path = sys.argv[1]
    if os.path.isfile(nso_file_path):
        read_nso_header(nso_file_path)
    else:
        print("NSO file not found")

