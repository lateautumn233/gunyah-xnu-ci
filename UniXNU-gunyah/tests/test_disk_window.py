#!/usr/bin/env python3
"""Exercise overflow, EOF and malformed window selection against C++ code."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = r'''
#include <cassert>
#include "GunyahDiskWindow.h"
using namespace GunyahDiskWindow;
int main() {
    uint64_t n;
    assert(decimal("2048", n) && n == 2048);
    assert(decimal("18446744073709551615", n) && n == UINT64_MAX);
    for (auto s : {"", "-1", "+1", " 1", "1x", "0x800", "18446744073709551616",
                   "000000000000000000000", "999999999999999999999999999999999999999999999999999999999999999"})
        assert(!decimal(s, n));
    assert(valid(69632, 2048, 65536));
    assert(valid(65536, 0, 65536));
    assert(valid(65536, 65535, 1));
    assert(!valid(65536, 65536, 1));
    assert(!valid(65536, 2048, 65536));
    assert(!valid(65536, 0, 0));
    assert(!valid(UINT64_MAX, 0, 1));
    assert(!valid(100, UINT64_MAX, 2));
    assert(!valid(100, 1, UINT64_MAX));
}
'''
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory)
    (path/'test.cpp').write_text('#include <initializer_list>\n' + source)
    subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                    '-I'+str(root/'drivers/ArmDTPlatform'), path/'test.cpp', '-o', path/'test'], check=True)
    subprocess.run([path/'test'], check=True)
print('Disk window: decimal, overflow, bounds and EOF validation PASS')
