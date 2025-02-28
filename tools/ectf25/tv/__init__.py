"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import binascii
import json
from queue import Queue
import socket
import threading
import time

from loguru import logger

from ectf25.utils.decoder import DecoderIntf


class DecoderError(Exception):
    """Error thrown by the Decoder"""

    pass


class TV:
    """Robust TV class for full end-to-end setup

    You can use ectf25.utils.tester for a lighter-weight development setup

    See https://rules.ectf.mitre.org/2025/getting_started/boot_reference
    """

    BLOCK_LEN = 256

    def __init__(self, sat_host: str, sat_port: int, dec_port: str, dec_baud: int):
        """
        :param sat_host: TCP host for the Satellite
        :param sat_port: TCP port for the Satellite
        :param dec_port: Serial port to the Decoder
        :param dec_baud: Baud rate of the Decoder serial interface
        """
        self.sat_host = sat_host
        self.sat_port = sat_port
        self.decoder = DecoderIntf(dec_port)
        self.to_decode = Queue()
        self.crash = threading.Event()

    def downlink(self):
        """Receive frames from the Satellite and queue them to be sent to the Decoder"""
        logger.info(f"Connecting to satellite at {self.sat_host}:{self.sat_port}")

        try:
            # Open connection to the Satellite
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.sat_host, self.sat_port))

            while not self.crash.is_set():
                line = b""
                while not line.endswith(b"\n"):
                    if (cur_byte := s.recv(1)) == b"":  # connection closed
                        raise RuntimeError("Failed to receive from satellite")
                    line += cur_byte
                
                frame = json.loads(line)
                channel = frame["channel"]
                timestamp = frame["timestamp"]
                encoded = binascii.a2b_hex(frame.pop("encoded"))

                # Debug: Confirmar que llega un paquete cifrado
                logger.debug(f" Recibido de Satellite ({channel}, {timestamp}): {encoded}")

                # Agregar paquete a la cola
                self.to_decode.put_nowait(encoded)

                #  Debug: Confirmar que el paquete se agregó a la cola
                logger.debug(f"Paquete encolado para decodificar: {encoded}")

        except ConnectionRefusedError:
            logger.critical(f"No se pudo conectar al Satellite en {self.sat_host}:{self.sat_port}")
            self.crash.set()
        except Exception as e:
            logger.critical(f"Downlink CRASHED: {e}")
            self.crash.set()
            raise

    def decode(self):
        """Serve frames from the queue to the Decoder, printing the decoded results"""
        logger.info("Iniciando decodificación...")

        try:
            while not self.crash.is_set():
                queue_size = self.to_decode.qsize()
                logger.debug(f"Extrayendo paquete de la cola: {queue_size}")

                if not self.to_decode.empty():
                    encoded = self.to_decode.get_nowait()
                    logger.debug(f"Extrayendo paquete de la cola: {encoded}")

                    try:
                        #  Capturar posibles errores al llamar al decoder
                        decoded = self.decoder.decode(encoded)
                        if decoded:
                            logger.debug(f" Respuesta del decoder.c: {decoded}")
                            logger.opt(colors=True).info(f"<red> Decodificado:</red> <red>{decoded}</red>")
                        else:
                            logger.error("Decoder en C no devolvió ningún dato.")
                    except Exception as e:
                        logger.error(f" Error al ejecutar decoder.decode(): {e}")

        except Exception as e:
            logger.critical(f" Decoder CRASHED: {e}")
            self.crash.set()
            raise


    def run(self):
        """Run the TV, connecting to the Satellite and the Decoder"""

        try:
            decode = threading.Thread(target=self.decode)
            decode.start()
            downlink = threading.Thread(target=self.downlink, daemon=True)
            downlink.start()
            while downlink.is_alive() and decode.is_alive():
                # Main thread sleeps waiting for ctrl+c from user or threads to crash.
                # We have to busy wait here because if we decode.join(), the main thread
                # does not receive the KeyboardInterrupt exception. Main thread sleeps
                # to prevent using the CPU during the spin lock. The main thread will
                # still receive the keyboard interrupt in the sleep.
                time.sleep(0.1)
        except KeyboardInterrupt:  # expect exit from user
            pass
        finally:
            self.crash.set()
