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

# RSA (generación, firma y verificación)

def is_probable_prime(n: int, k: int = 8) -> bool:
    if n < 2:
        return False
    small_primes = (2,3,5,7,11,13,17,19,23,29)
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 = d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate

def egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No existe inverso modular.")
    return x % m
