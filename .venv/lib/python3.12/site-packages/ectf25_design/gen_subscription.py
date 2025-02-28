#!/usr/bin/env python3
"""
gen_subscription.py
-------------------
Genera el código de suscripción para un decodificador usando una clave específica por canal.
El código de suscripción se genera a partir de:
  - CH_ID (4 bytes)
  - DECODER_ID (4 bytes)
  - TS_START (4 bytes) [timestamp de inicio, 32 bits]
  - TS_END (4 bytes) [timestamp de expiración, 32 bits]
  --> Total: 16 bytes
Luego se calcula un HMAC (16 bytes) usando la clave específica del canal (K_CHANNEL_ID) obtenida de los Global Secrets (GS),
para obtener un código de suscripción final de 32 bytes con el siguiente formato:
  {CH_ID || DECODER_ID || TS_START || TS_END || HMAC_CODE}

Requisitos de ejecución:
  1. El archivo de secretos (generado con gen_secrets.py) debe contener un diccionario "channel_keys" con las claves de cada canal.
     Por ejemplo:
         {
           "channels": [1, 2, 3],
           "K_master": "...",
           "KMAC": "...",
           "partial_keys": { ... },
           "channel_keys": {
              "1": "base64_encoded_key_for_channel1",
              "2": "base64_encoded_key_for_channel2",
              "3": "base64_encoded_key_for_channel3"
           }
         }
  2. Para generar la suscripción, se debe proporcionar:
      - secrets_file: ruta al archivo de secretos (por ejemplo, secrets.json)
      - subscription_file: ruta al archivo de salida para la suscripción (por ejemplo, subscription.bin)
      - device_id: ID del decodificador (DECODER_ID)
      - start: timestamp de inicio (TS_START)
      - end: timestamp de expiración (TS_END)
      - channel: canal (CH_ID) al que se suscribe
     
Ejemplo de ejecución:
    python gen_subscription.py secrets.json subscription.bin 1 1610000000 1610003600 2
"""

import argparse
import json
import struct
import base64

def derive_cmac(key: bytes, data: bytes) -> bytes:
    """
    Calcula el MAC usando AES-CMAC.
    Se utiliza para generar el HMAC_CODE.
    """
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()

def gen_subscription(secrets: bytes, device_id: int, start: int, end: int, channel: int) -> bytes:
    """
    Genera el código de suscripción.

    Parámetros:
      - secrets: contenido del archivo de secretos (JSON) que contiene los Global Secrets (GS), incluyendo "channel_keys".
      - device_id: ID del decodificador (DECODER_ID).
      - start: Timestamp de inicio de la suscripción (TS_START, 32 bits).
      - end: Timestamp de expiración de la suscripción (TS_END, 32 bits).
      - channel: Canal (CH_ID) al que se suscribe.

    Retorna:
      - Código de suscripción de 32 bytes en el formato:
            {CH_ID (4 bytes) || DECODER_ID (4 bytes) || TS_START (4 bytes) || TS_END (4 bytes) || HMAC_CODE (16 bytes)}
    """
    secrets_data = json.loads(secrets)
    
    # Se obtiene la clave específica del canal desde GS.
    # Se asume que GS contiene un diccionario "channel_keys" indexado por el número de canal (como cadena).
    if "channel_keys" not in secrets_data:
        raise ValueError("El archivo de secretos no contiene 'channel_keys'.")
    channel_key_b64 = secrets_data["channel_keys"].get(str(channel))
    if channel_key_b64 is None:
        raise ValueError(f"No se encontró la clave para el canal {channel} en GS.")
    channel_key = base64.b64decode(channel_key_b64)
    
    # Empaquetar los 4 enteros (16 bytes) en el orden: CH_ID, DECODER_ID, TS_START, TS_END.
    # Se utiliza el formato '<IIII' (little-endian, 4 enteros de 4 bytes cada uno).
    subscription_data = struct.pack("<IIII", channel, device_id, start, end)
    
    # Calcular HMAC_CODE (16 bytes) usando la clave específica del canal (K_CHANNEL_ID).
    hmac_code = derive_cmac(channel_key, subscription_data)
    
    # Concatenar para formar el código de suscripción final de 32 bytes.
    subscription_code = subscription_data + hmac_code
    
    print(f"\n[gen_subscription] Subscription final (length = {len(subscription_code)} bytes): {subscription_code.hex()}\n")
    return subscription_code

def parse_args():
    parser = argparse.ArgumentParser(
        description="Genera el código de suscripción para un decodificador utilizando la clave específica del canal."
    )
    parser.add_argument("--force", "-f", action="store_true", help="Sobreescribir archivo de suscripción existente.")
    parser.add_argument("secrets_file", type=str, help="Ruta al archivo de secretos generado con gen_secrets.py")
    parser.add_argument("subscription_file", type=str, help="Archivo de salida para la suscripción")
    parser.add_argument("device_id", type=int, help="ID del decodificador (DECODER_ID)")
    parser.add_argument("start", type=int, help="Timestamp de inicio de la suscripción (32-bit)")
    parser.add_argument("end", type=int, help="Timestamp de expiración de la suscripción (32-bit)")
    parser.add_argument("channel", type=int, help="Canal (CH_ID) al que se suscribe")
    return parser.parse_args()

def main():
    args = parse_args()
    # Leer el archivo de secretos
    with open(args.secrets_file, "rb") as f:
        secrets = f.read()
    # Generar la suscripción usando los parámetros proporcionados
    subscription = gen_subscription(secrets, args.device_id, args.start, args.end, args.channel)
    # Escribir el código de suscripción en el archivo de salida
    mode = "wb" if args.force else "xb"
    with open(args.subscription_file, mode) as f:
        f.write(subscription)
    print(f"\n[gen_subscription] Código de suscripción generado en {args.subscription_file}\n")

if __name__ == "__main__":
    main()
