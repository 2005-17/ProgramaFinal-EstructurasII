import secrets
import math
import json
import base64
import sys

# Hash FNV-1 (64-bit)

def fnv1_hash(data: bytes) -> int:
    FNV_offset_basis = 0xcbf29ce484222325
    FNV_prime = 0x100000001b3
    h = FNV_offset_basis
    for b in data:
        h = (h * FNV_prime) & 0xFFFFFFFFFFFFFFFF
        h = h ^ b
    return h

def fnv1_hex(data: bytes) -> str:
    return format(fnv1_hash(data), '016x')

# Compresión RLE (simple)

def rle_compress(data: bytes) -> bytes:
    if not data:
        return b''
    out = bytearray()
    prev = data[0]
    count = 1
    for b in data[1:]:
        if b == prev and count < 255:
            count += 1
        else:
            out.append(count)
            out.append(prev)
            prev = b
            count = 1
    out.append(count)
    out.append(prev)
    return bytes(out)

def rle_decompress(data: bytes) -> bytes:
    if not data:
        return b''
    if len(data) % 2 != 0:
        raise ValueError("Formato RLE incorrecto.")
    out = bytearray()
    for i in range(0, len(data), 2):
        cnt = data[i]
        val = data[i+1]
        out.extend(bytes([val]) * cnt)
    return bytes(out)
