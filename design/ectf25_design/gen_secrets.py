#!/usr/bin/env python3
"""
gen_secrets.py
---------------
Genera el archivo de secretos (Global Secrets, GS) para el sistema.
El archivo contendrá lo siguiente:
  - "channels": la lista de canales válidos.
  - "channel_keys": una clave específica de 256 bits (32 bytes) generada aleatoriamente para cada canal.
  - "KMAC": una clave de autenticación de 16 bytes.
  - "partial_keys": claves parciales (simulación de TSS) para cada decodificador, generadas aleatoriamente (en este ejemplo, 16 bytes cada una).

El output se usará en otros módulos; en particular, la suscripción se generará usando la clave específica del canal (K_CHANNEL_ID) y el HMAC se calculará con KMAC.
El formato final de GS, según lo solicitado, es:
  {K1 || K2 || K3 || KMAC}
  (aquí "K1", "K2", "K3" corresponden a las claves de cada canal).

Instrucciones de ejecución:
  Ejemplo de uso:
    python gen_secrets.py secrets.json 1 2 3 4

  Donde:
    - "secrets.json" es el archivo de salida que se creará.
    - Los siguientes números (1 2 3) son los canales válidos (excluyendo el canal 0).
    - El último número (4) es el número de decodificadores para los cuales se generarán las claves parciales.
"""

import argparse
import json
import os
import base64
from typing import List

def derive_cmac(key: bytes, data: bytes) -> bytes:
    """
    Calcula el MAC usando AES-CMAC.
    Se utiliza para generar el HMAC en otros procesos.
    """
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()

def gen_secrets(channels: List[int], num_decoders: int = 8) -> bytes:
    """
    Genera el archivo de secretos con claves seguras para el sistema.

    Parámetros:
      - channels: lista de canales válidos (excluyendo canal 0).
      - num_decoders: número de decodificadores para los cuales se generarán claves parciales (por defecto 8).

    Salida:
      - Un JSON codificado en bytes que contiene:
          "channels": la lista de canales,
          "channel_keys": un diccionario con claves específicas por canal (cada una de 256 bits, es decir, 32 bytes, codificadas en base64),
          "KMAC": clave de autenticación (16 bytes, codificada en base64),
          "partial_keys": un diccionario con claves parciales para cada decodificador (16 bytes, codificadas en base64).
    """
    # Generar KMAC de 16 bytes
    KMAC = os.urandom(16)

    # Generar claves específicas por canal: para cada canal de la lista, se genera un valor aleatorio de 32 bytes
    channel_keys = {str(channel): base64.b64encode(os.urandom(32)).decode('utf-8') for channel in channels}

    # Generar claves parciales para cada decodificador (simulación de TSS)
    partial_keys = {f"decoder_{i}": base64.b64encode(os.urandom(16)).decode('utf-8') for i in range(1, num_decoders + 1)}

    # Construir el diccionario de secretos
    secrets = {
        "channels": channels,
        "channel_keys": channel_keys,
        "KMAC": base64.b64encode(KMAC).decode('utf-8'),
        "partial_keys": partial_keys
    }

    # Convertir a JSON y codificar en bytes
    secrets_json = json.dumps(secrets, indent=2)
    print(f"\n[gen_secrets] Final secrets JSON generated (total length = {len(secrets_json.encode('utf-8'))} bytes).\n")
    return secrets_json.encode('utf-8')

def parse_args():
    """
    Define y analiza los argumentos de línea de comandos.
    
    Uso:
      python gen_secrets.py secrets_file channel1 channel2 ... [num_decoders]

    Ejemplo:
      python gen_secrets.py secrets.json 1 2 3 4
      (donde 1, 2 y 3 son los canales válidos y 4 es el número de decodificadores)
    """
    parser = argparse.ArgumentParser(
        description="Genera el archivo de secretos para el sistema."
    )
    parser.add_argument("--force", "-f", action="store_true", help="Sobreescribir archivo de secretos existente.")
    parser.add_argument("secrets_file", type=str, help="Ruta del archivo de secretos a crear.")
    parser.add_argument("channels", nargs="+", type=int, help="Lista de canales válidos (excluyendo canal 0).")
    parser.add_argument("num_decoders", nargs="?", type=int, default=8, help="Número de decodificadores a generar (por defecto 8).")
    return parser.parse_args()

def main():
    """
    Función principal.
    Lee los argumentos, genera los secretos y escribe el archivo de salida.
    """
    args = parse_args()

    # Si no se pasa el número de decoders
    if len(args.num_decoders) == 0:
        args.num_decoders = 8
        
    secrets_data = gen_secrets(args.channels, args.num_decoders)
    mode = "wb" if args.force else "xb"
    with open(args.secrets_file, mode) as f:
        f.write(secrets_data)
    print(f"\n[gen_secrets] Archivo de secretos generado en {args.secrets_file}\n")

if __name__ == "__main__":
    main()
