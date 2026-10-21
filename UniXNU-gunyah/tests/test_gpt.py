#!/usr/bin/env python3
"""Exercise the actual kernel GPT selector with CRC-valid adversarial tables."""
import argparse
from pathlib import Path
import struct
import subprocess
import tempfile
import uuid
import zlib

root = Path(__file__).resolve().parents[1]
source = r'''
#include <fstream>
#include <vector>
#include <iostream>
#include <cstring>
#include "GunyahGpt.h"
static bool readDisk(void *ctx, uint64_t at, uint32_t n, void *out) {
 auto &data=*static_cast<std::vector<uint8_t> *>(ctx);
 if (at>data.size() || n>data.size()-at) return false;
 memcpy(out,data.data()+at,n); return true;
}
int main(int argc,char **argv) {
 if(argc!=3) return 2;
 std::ifstream input(argv[1],std::ios::binary);
 std::vector<uint8_t> data((std::istreambuf_iterator<char>(input)),{});
 std::vector<uint8_t> work(GunyahGpt::WorkspaceBytes);
 GunyahGpt::Selection result={};
 auto error=GunyahGpt::select(readDisk,&data,data.size()/512,argv[2],work.data(),result);
 if(error) std::cout<<error;
 else std::cout<<result.start<<":"<<result.count<<":"<<result.index;
}
'''


def fix(data, entries=False):
    if entries:
        data[-33*512:-512] = data[1024:1024+16384]
        crc = zlib.crc32(data[1024:1024+16384])
        for at in (512, len(data)-512):
            struct.pack_into('<I', data, at+88, crc)
    for at in (512, len(data)-512):
        struct.pack_into('<I', data, at+16, 0)
        struct.pack_into('<I', data, at+16, zlib.crc32(data[at:at+92]))


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--image',type=Path,required=True)
    args=p.parse_args()
    original=args.image.read_bytes()
    wanted=str(uuid.UUID(bytes_le=original[1040:1056]))
    with tempfile.TemporaryDirectory() as temp:
        tmp=Path(temp);(tmp/'test.cpp').write_text(source)
        subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=undefined',
                        '-I'+str(root/'drivers/ArmDTPlatform'),tmp/'test.cpp','-o',tmp/'test'],check=True)
        tests=0
        def check(data, expected, selector=wanted):
            nonlocal tests
            (tmp/'disk').write_bytes(data)
            got=subprocess.check_output([tmp/'test',tmp/'disk',selector],text=True)
            assert got==expected,(got,expected)
            tests+=1
        check(original,'2048:65536:1')
        check(original,'2048:65536:1',wanted.upper())
        for value in ('', '0'*36, wanted+'x', wanted[:-1], '00000000-0000-0000-0000-000000000000'):
            check(original,'uuid',value)
        check(original,'uuid-not-found','11111111-2222-3333-4444-555555555555')
        for at in (512+16,len(original)-512+16):
            d=bytearray(original);d[at]^=1;check(d,'header')
        for at in (1024+127,len(original)-33*512+127):
            d=bytearray(original);d[at]^=1;check(d,'entries-crc')
        d=bytearray(original);d[450]=0;check(d,'protective-mbr')
        d=bytearray(original);struct.pack_into('<Q',d,512+72,3);fix(d);check(d,'header-mismatch')
        d=bytearray(original);d[-512+56]^=1;fix(d);check(d,'header-mismatch')
        for start,end in ((0,67583),(2048,len(original)//512-1),(2048,2047)):
            d=bytearray(original);struct.pack_into('<QQ',d,1024+32,start,end);fix(d,True);check(d,'partition-range')
        d=bytearray(original);d[1024]^=1;fix(d,True);check(d,'partition-type')
        d=bytearray(original);d[1152:1280]=d[1024:1152];fix(d,True);check(d,'partition-conflict')
        d=bytearray(original);d[1152:1280]=d[1024:1152];d[1168]^=1;fix(d,True);check(d,'partition-conflict')
        # Backup copy CRC passes individually, but primary/backup entries differ.
        d=bytearray(original);d[-33*512+127]^=1
        struct.pack_into('<I',d,len(d)-512+88,zlib.crc32(d[-33*512:-512]));fix(d)
        check(d,'header-mismatch')
        print(f'GPT selector: {tests} valid/corrupt/CRC-repaired/UUID cases PASS')


if __name__=='__main__': main()
