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

def generate_rsa_keypair(bits_per_prime: int = 512) -> dict:
    # Genera p y q, luego (n, e, d)
    p = generate_prime(bits_per_prime)
    q = generate_prime(bits_per_prime)
    while q == p:
        q = generate_prime(bits_per_prime)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}

def rsa_sign_integer(m: int, private: dict) -> int:
    return pow(m, private['d'], private['n'])

def rsa_recover_from_signature(sig: int, public: dict) -> int:
    return pow(sig, public['e'], public['n'])

# Conversión y utilidades

def int_to_hex(i: int) -> str:
    return format(i, 'x')

def hex_to_int(h: str) -> int:
    return int(h, 16)

def bytes_to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

def b64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))

# Interfaz y flujo principal

def menu_text() -> str:
    return """
===== MENÚ =====
1. Ingresar mensaje
2. Calcular hash FNV-1
3. Comprimir mensaje (RLE)
4. Generar claves RSA y firmar hash
5. Simular envío (guardar paquete en memoria)
6. Descomprimir y verificar firma (usar clave pública)
7. Mostrar estado de autenticidad
8. Exportar paquete a archivo (JSON)
9. Importar paquete desde archivo (JSON)
0. Salir
"""

def main():
    mensaje = None            # str
    mensaje_bytes = None      # bytes
    hash_hex = None           # str hex 16 caracteres (64-bit)
    comprimido = None         # bytes
    clave_priv = None         # dict RSA (contiene d)
    clave_pub = None          # dict RSA pública (n,e)
    firma_int = None          # int
    paquete_enviado = None    # dict {compressed, signature, pub_key}
    autenticidad = None       # None/True/False

    print("Programa de firma y verificación de mensajes.")
    print("Trabaja paso a paso con el menú. Si algo falla, selecciona la opción correcta nuevamente.\n")

    while True:
        print(menu_text())
        try:
            op = int(input("Opción: ").strip())
        except ValueError:
            print("Ingrese un número del menú.\n")
            continue

        if op == 0:
            print("Hasta luego.")
            break

        elif op == 1:
            texto = input("Escribe tu mensaje: ")
            mensaje = texto
            mensaje_bytes = mensaje.encode('utf-8')
            # resetear downstream
            hash_hex = None
            comprimido = None
            clave_priv = None
            clave_pub = None
            firma_int = None
            paquete_enviado = None
            autenticidad = None
            print("Mensaje guardado.\n")

        elif op == 2:
            if mensaje_bytes is None:
                print("Primero ingresa un mensaje (opción 1).\n")
                continue
            hash_hex = fnv1_hex(mensaje_bytes)
            print(f"Hash FNV-1 (64-bit) -> {hash_hex}\n")

        elif op == 3:
            if mensaje_bytes is None:
                print("No hay mensaje. Usa la opción 1.\n")
                continue
            antes = len(mensaje_bytes)
            comprimido = rle_compress(mensaje_bytes)
            despues = len(comprimido)
            print(f"Tamaño original: {antes} bytes")
            print(f"Tamaño comprimido: {despues} bytes\n")

        elif op == 4:
            if hash_hex is None:
                print("Calcula el hash primero (opción 2).\n")
                continue
            print("Generando par RSA (esto puede tomar unos segundos)...")
            clave = generate_rsa_keypair(bits_per_prime=512)
            clave_priv = clave
            clave_pub = {'n': clave['n'], 'e': clave['e']}
            # firmar hash (convertir hex -> int)
            h_int = hex_to_int(hash_hex)
            firma_int = rsa_sign_integer(h_int, clave_priv)
            print("Claves generadas. (La privada no se debe enviar.)")
            print(f"Clave pública n (hex, truncado): {int_to_hex(clave_pub['n'])[:64]}...")
            print(f"Clave pública e: {clave_pub['e']}")
            # mostrar parte de d sólo para inspección
            print(f"Clave privada d (hex, truncada): {int_to_hex(clave_priv['d'])[:64]}...\n")
            print(f"Firma (hex, truncada): {int_to_hex(firma_int)[:64]}...\n")

        elif op == 5:
            if comprimido is None:
                print("Comprime el mensaje primero (opción 3).\n")
                continue
            if firma_int is None or clave_pub is None:
                print("Genera la firma y la clave pública (opción 4).\n")
                continue
            # Simular envío: paquete en memoria
            paquete_enviado = {
                'compressed_message': bytes_to_b64(comprimido),
                'signature_hex': int_to_hex(firma_int),
                'pub_key': {
                    'n_hex': int_to_hex(clave_pub['n']),
                    'e': clave_pub['e']
                }
            }
            autenticidad = None
            print("Paquete preparado y 'enviado' (simulado en memoria). No se transmitió la clave privada.\n")

        elif op == 6:
            if paquete_enviado is None:
                print("No hay paquete. Usa la opción 5 para enviar.\n")
                continue
            try:
                comp_b = b64_to_bytes(paquete_enviado['compressed_message'])
                pub = {
                    'n': hex_to_int(paquete_enviado['pub_key']['n_hex']),
                    'e': paquete_enviado['pub_key']['e']
                }
                sig = hex_to_int(paquete_enviado['signature_hex'])
            except Exception as e:
                print("Error leyendo el paquete:", e, "\n")
                continue
            # Descomprimir
            try:
                recibido = rle_decompress(comp_b)
            except Exception as e:
                print("Error al descomprimir el mensaje recibido:", e, "\n")
                autenticidad = False
                continue
            # Calcular hash y comparar con firma
            hash_recv = fnv1_hash(recibido)
            recovered = rsa_recover_from_signature(sig, pub)
            print(f"Hash calculado del mensaje recibido: {format(hash_recv,'016x')}")
            print(f"Hash recuperado desde la firma:       {format(recovered,'016x')}")
            if recovered == hash_recv:
                autenticidad = True
                print("Resultado: Mensaje auténtico y no modificado.\n")
            else:
                autenticidad = False
                print("Resultado: Mensaje alterado o firma no válida.\n")

        elif op == 7:
            if autenticidad is None:
                print("Aún no se verificó. Usa la opción 6 primero.\n")
            elif autenticidad is True:
                print("Estado: Mensaje auténtico y no modificado.\n")
            else:
                print("Estado: Mensaje alterado o firma no válida.\n")

        elif op == 8:
            # Exportar paquete a archivo JSON
            if paquete_enviado is None:
                print("No hay paquete para exportar. Genera y envía primero (opciones 4 y 5).\n")
                continue
            filename = input("Nombre de archivo para exportar (ej: paquete.json): ").strip()
            if not filename:
                print("Nombre inválido.\n")
                continue
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(paquete_enviado, f, ensure_ascii=False, indent=2)
                print(f"Paquete exportado a '{filename}'.\n")
            except Exception as e:
                print("Error al exportar:", e, "\n")

        elif op == 9:
            # Importar paquete desde archivo JSON
            filename = input("Ruta del archivo a importar (ej: paquete.json): ").strip()
            if not filename:
                print("Nombre inválido.\n")
                continue
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                # validar campos mínimos
                if 'compressed_message' in data and 'signature_hex' in data and 'pub_key' in data:
                    paquete_enviado = data
                    autenticidad = None
                    print(f"Paquete importado desde '{filename}'. Ahora puedes verificarlo (opción 6).\n")
                else:
                    print("El archivo no contiene el formato esperado.\n")
            except FileNotFoundError:
                print("Archivo no encontrado.\n")
            except Exception as e:
                print("Error al importar:", e, "\n")

        else:
            print("Opción no reconocida. Intenta otra vez.\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario. Saliendo.")
        sys.exit(0)