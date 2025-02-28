#!/usr/bin/env python3
"""
encoder.py
----------
Combina la lógica de:
  - Frame de 8 bytes (truncado o relleno con ceros) + trailer(16) -> 24 bytes cifrados en AES-CTR
  - Suscripción de 52 bytes con CMAC manual (RFC4493)
  - Diccionario de claves por canal: "channel_keys" en el JSON, y KMAC (16 bytes) si hace falta

El paquete final mide:
  header(20) + subscription(52) + ciphertext(24) = 96 bytes

Uso de ejemplo:
  python encoder.py secrets.json 2 "HolaMundoBien" 1610001234

Se leerá secrets.json, donde se espera:
  {
    "channel_keys": {
      "2": "...(base64)...",
      ...
    },
    "KMAC": "...(base64 16 bytes)..."
  }

Salida:
  - Imprime en pantalla en HEX el paquete resultante (96 bytes).
"""

import argparse
import struct
import json
import base64
import os

from Crypto.Cipher import AES

def red_print(msg, explanation):
    """
    Imprime en rojo el mensaje y una breve explicación.
    """
    print("\033[31m" + msg + " -> " + explanation + "\033[0m")

# ---------------- Implementación manual de AES-CMAC (RFC4493) ----------------
def leftshift_onebit(block16: bytes) -> bytearray:
    out = bytearray(16)
    overflow = 0
    for i in reversed(range(16)):
        out[i] = ((block16[i] << 1) & 0xFE) | overflow
        overflow = 1 if (block16[i] & 0x80) else 0
    return out

def aes_ecb_encrypt_block(key: bytes, block16: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block16)

def aes_cmac(key: bytes, msg: bytes) -> bytes:
    """
    Implementación de AES-CMAC (RFC4493).
    """
    zero16 = b'\x00' * 16
    L = aes_ecb_encrypt_block(key, zero16)

    L_arr = bytearray(L)
    K1 = leftshift_onebit(L_arr)
    if (L_arr[0] & 0x80) != 0:
        K1[15] ^= 0x87

    K2 = leftshift_onebit(K1)
    if (K1[0] & 0x80) != 0:
        K2[15] ^= 0x87

    n = (len(msg) + 15) // 16
    complete = (len(msg) % 16 == 0 and len(msg) != 0)
    if n == 0:
        n = 1
        complete = False
    
    if complete:
        last_block = msg[(n-1)*16 : n*16]
        last = bytes(x ^ y for x,y in zip(last_block, K1))
    else:
        rem = len(msg) % 16
        temp = bytearray(16)
        temp[:rem] = msg[(n-1)*16 : (n-1)*16 + rem]
        temp[rem] = 0x80
        last = bytes(x ^ y for x,y in zip(temp, K2))

    cipher = AES.new(key, AES.MODE_ECB)
    X = bytearray(16)
    for i in range(n-1):
        block = bytes(a ^ b for a,b in zip(X, msg[i*16 : i*16+16]))
        X = bytearray(cipher.encrypt(block))
    block = bytes(a ^ b for a,b in zip(X, last))
    X = bytearray(cipher.encrypt(block))
    return bytes(X)
# ------------------------------------------------------------------------------

def store64_be(val: int) -> bytes:
    """
    Almacena 'val' en 8 bytes big-endian.
    """
    return bytes([
        (val >> 56) & 0xFF,
        (val >> 48) & 0xFF,
        (val >> 40) & 0xFF,
        (val >> 32) & 0xFF,
        (val >> 24) & 0xFF,
        (val >> 16) & 0xFF,
        (val >>  8) & 0xFF,
        (val >>  0) & 0xFF,
    ])

class Encoder:
    MAX_FRAME_SIZE = 8  # Ahora el frame se trunca / rellena a 8 bytes
    def __init__(self, secrets_json: bytes):
        """
        Carga la información de channel_keys y KMAC del archivo JSON.
        """
        data = json.loads(secrets_json)

        # KMAC si estuviera
        self.KMAC = base64.b64decode(data["KMAC"]) if "KMAC" in data else None

        # channel_keys
        if "channel_keys" not in data:
            raise ValueError("No se encontró 'channel_keys' en el JSON.")
        self.channel_keys = data["channel_keys"]

        # Llevamos un contador seq
        self.seq = 0
        self.encoder_id = 1

    def _get_channel_key(self, channel: int) -> bytes:
        """
        Decodifica la clave del canal desde base64.
        """
        key_b64 = self.channel_keys.get(str(channel))
        if not key_b64:
            raise ValueError(f"No se encontró clave para el canal {channel}.")
        return base64.b64decode(key_b64)

    def _derive_dynamic_key(self, K_channel: bytes, seq: int, channel: int) -> bytes:
        """
        1) K1 = CMAC(K_channel, b"K1-Derivation")
        2) dynamic_key = CMAC(K1, [seq, channel] en LE)
        """
        K1 = aes_cmac(K_channel, b"K1-Derivation")
        data_le = struct.pack("<I I", seq, channel)
        dynamic_key = aes_cmac(K1, data_le)
        red_print(f"[encoder] dynamic_key={dynamic_key.hex()}",
                  "Derivado con CMAC.")
        return dynamic_key

    def _encrypt_24bytes(self, dynamic_key: bytes, frame_8: bytes,
                         timestamp: int, seq: int, channel: int) -> bytes:
        """
        Cifra con AES-CTR 24 bytes: frame_8 + trailer(16).
        Nonce: 8 ceros + seq en big-endian (8).
        """
        big_end_seq = store64_be(seq)
        nonce = b"\x00"*8 + big_end_seq

        # Trailer(16) => <Q I I> en LE => (timestamp(8), seq(4), channel(4))
        trailer = struct.pack("<Q I I", timestamp, seq, channel)

        plaintext_24 = frame_8 + trailer  # 8 +16 =24
        cipher = AES.new(dynamic_key, AES.MODE_CTR, initial_value=nonce, nonce=b"")
        return cipher.encrypt(plaintext_24)

    def encode(self, channel: int, input_msg: bytes, timestamp: int) -> bytes:
        self.seq += 1
        seq = self.seq

        # 1) Forzar a 8 bytes
        if len(input_msg) > self.MAX_FRAME_SIZE:
            input_msg = input_msg[:self.MAX_FRAME_SIZE]
        frame_8 = input_msg.ljust(self.MAX_FRAME_SIZE, b'\x00')

        # 2) Cargar la clave del canal
        K_channel = self._get_channel_key(channel)

        # 3) Derivar dynamic_key
        dynamic_key = self._derive_dynamic_key(K_channel, seq, channel)

        # 4) Cifrar => 24 bytes
        ciph_24 = self._encrypt_24bytes(dynamic_key, frame_8, timestamp, seq, channel)

        # 5) Header(20) => <I I I Q> (seq, channel, encoder_id, timestamp) en LE
        header = struct.pack("<I I I Q", seq, channel, self.encoder_id, timestamp)

        # 6) Suscripción(52). Ejemplo => 36 +16 CMAC
        #   36 => 5 enteros <I I I I I> + partial_key(16)
        subscription_fields = struct.pack("<IIIII", 1, 1000, 2000, channel, self.encoder_id)
        partial_key = b"1234567890abcdef"  # 16
        subs_36 = subscription_fields + partial_key
        #   CMAC con K_channel (o KMAC, depende tu diseño)
        mac_16 = aes_cmac(K_channel, subs_36)
        subscription52 = subs_36 + mac_16

        # 7) Paquete => 20 + 52 + 24 = 96
        packet = header + subscription52 + ciph_24

        print("Sent pkt....:")
        print(packet.hex())
        print("----------------------------------------------------------")
        
        return packet

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("secrets_file", type=argparse.FileType("rb"),
                        help="Archivo JSON con 'channel_keys' y opcional 'KMAC'")
    parser.add_argument("channel", type=int, help="Canal ID")
    parser.add_argument("frame", help="Mensaje a enviar (se ajustará a 8 bytes)")
    parser.add_argument("timestamp", type=int, help="Timestamp de 64 bits (usado en trailer)")
    args = parser.parse_args()

    enc = Encoder(args.secrets_file.read())
    packet = enc.encode(args.channel, args.frame.encode(), args.timestamp)
    print(packet.hex())

if __name__ == "__main__":
    main()
