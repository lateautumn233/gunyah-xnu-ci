#!/usr/bin/env python3
"""Compile the freestanding parser and compare real launchd DER against XML."""
import argparse
import ctypes as C
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


class View(C.Structure):
    _fields_ = [('bytes', C.POINTER(C.c_ubyte)), ('size', C.c_size_t)]


class Entry(C.Structure):
    _fields_ = [('key', View), ('value', View), ('type', C.c_ubyte)]


class Context(C.Structure):
    _fields_ = [('entries', Entry * 64), ('count', C.c_size_t)]


def tlv(tag, body):
    size = len(body)
    length = bytes([size]) if size < 128 else bytes([0x82]) + size.to_bytes(2, 'big') if size > 255 else bytes([0x81, size])
    return bytes([tag]) + length + body


def dictionary(pairs):
    return tlv(0x70, b'\x02\x01\x01' + tlv(0xb0, b''.join(tlv(0x30, tlv(12, k) + v) for k, v in pairs)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--launchd', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    data = args.launchd.read_bytes()
    pins = json.loads((ROOT / 'configs/iphone10-3-20H392.json').read_text())
    import hashlib
    assert hashlib.sha256(data).hexdigest() == pins['files']['sbin/launchd']['sha256']
    at = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == 0x1d:
            offset, length = struct.unpack_from('<II', data, at + 8)
            signature = data[offset:offset + length]
        at += size
    blobs = {}
    for n in range(struct.unpack_from('>I', signature, 8)[0]):
        slot, offset = struct.unpack_from('>II', signature, 12 + n * 8)
        size = struct.unpack_from('>I', signature, offset + 4)[0]
        blobs[slot] = signature[offset + 8:offset + size]
    xml = plistlib.loads(blobs[5])
    with tempfile.TemporaryDirectory() as temp:
        lib = Path(temp) / 'entitlements.so'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
                        '-fsanitize=undefined', str(ROOT / 'UniXNU-gunyah/security/GunyahEntitlements.c'), '-o', str(lib)], check=True)
        api = C.CDLL(str(lib))
        api.ge_parse.argtypes = [C.c_void_p, C.c_size_t, C.POINTER(Context)]
        api.ge_boolean.argtypes = [C.POINTER(Context), C.c_char_p, C.c_size_t, C.POINTER(C.c_int)]
        api.ge_array_contains.argtypes = [C.POINTER(Context), C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.POINTER(C.c_int)]
        context = Context()
        def parse(raw):
            backing = C.create_string_buffer(raw)
            result = api.ge_parse(backing, len(raw), C.byref(context))
            return result, backing
        result, backing = parse(blobs[7])
        assert result == 0 and context.count == len(xml)
        decoded = {}
        for entry in context.entries[:context.count]:
            key = C.string_at(entry.key.bytes, entry.key.size).decode('ascii')
            raw = C.string_at(entry.value.bytes, entry.value.size)
            if entry.type == 1:
                decoded[key] = raw == b'\xff'
                value = C.c_int(-1)
                assert api.ge_boolean(C.byref(context), key.encode(), len(key), C.byref(value)) == 0
                assert bool(value.value) == xml[key]
            elif entry.type == 48:
                values = []
                while raw:
                    assert raw[0] == 12 and raw[1] < 128
                    values.append(raw[2:2 + raw[1]].decode('ascii'))
                    raw = raw[2 + raw[1]:]
                decoded[key] = values
                for text in values + ['not-present']:
                    value = C.c_int(-1)
                    assert api.ge_array_contains(C.byref(context), key.encode(), len(key), text.encode(), len(text), C.byref(value)) == 0
                    assert bool(value.value) == (text in values)
                assert api.ge_boolean(C.byref(context), key.encode(), len(key), C.byref(value)) == -3
            else:
                raise AssertionError('Unexpected real entitlement type')
        assert decoded == xml
        value = C.c_int(1)
        assert api.ge_boolean(C.byref(context), b'unknown', 7, C.byref(value)) == -2 and value.value == 0
        yes = b'\x01\x01\xff'
        synthetic = dictionary([(b'a', b'\x01\x01\0'), (b'b', tlv(12, b'text')), (b'c', tlv(48, b''))])
        result, backing = parse(synthetic)
        assert result == 0 and context.count == 3
        value = C.c_int(1)
        assert api.ge_boolean(C.byref(context), b'a', 1, C.byref(value)) == 0 and value.value == 0
        assert C.string_at(context.entries[1].value.bytes, context.entries[1].value.size) == b'text'
        assert api.ge_array_contains(C.byref(context), b'c', 1, b'x', 1, C.byref(value)) == 0 and value.value == 0
        assert api.ge_boolean(C.byref(context), b'b', 1, C.byref(value)) == -3
        negatives = [blobs[7][:-1], blobs[7] + b'\0', b'\x70\x80\0\0',
                     dictionary([(b'a', yes), (b'a', yes)]), dictionary([(b'b', yes), (b'a', yes)]),
                     dictionary([(b'a', b'\x01\x01\x01')]), dictionary([(b'a', b'\x02\x01\x01')]),
                     dictionary([(b'a\0', yes)]), dictionary([(b'a', tlv(48, yes))]),
                     dictionary([(b'a', tlv(48, tlv(12, b'x') * 33))]),
                     dictionary([(b'x' * 513, yes)]), dictionary([(f'{i:03}'.encode(), yes) for i in range(65)]),
                     blobs[7][:6] + b'\x02' + blobs[7][7:]]
        for raw in negatives:
            result, _ = parse(raw)
            assert result == -1 and context.count == 0
        # Every truncated prefix must reject, even after a successful parse.
        for size in range(len(blobs[7])):
            result, _ = parse(blobs[7][:size])
            assert result == -1 and context.count == 0
    args.output.write_text(json.dumps(dict(xml_der_values_equal=True, keys=len(xml),
        semantic_negative_cases=len(negatives), truncated_prefixes=len(blobs[7]),
        provider_registered=False, grants_applied=False), indent=2) + '\n')
    print(f'PASS: {len(xml)} XML/DER values equal; {len(negatives)} negative cases; all truncated prefixes rejected')


if __name__ == '__main__':
    main()
