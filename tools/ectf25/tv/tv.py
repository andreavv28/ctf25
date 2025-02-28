"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is provided only for educational purposes for the 2025 MITRE
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
        # Se pasa el baudrate al constructor del DecoderIntf
        self.decoder = DecoderIntf(dec_port, baudrate=dec_baud)
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
                    cur_byte = s.recv(1)
                    if cur_byte == b"":  # connection closed
                        raise RuntimeError("Failed to receive from satellite")
                    line += cur_byte

                frame = json.loads(line)
                channel = frame["channel"]
                timestamp = frame["timestamp"]
                encoded = binascii.a2b_hex(frame.pop("encoded"))

                # Debug: confirmar que se recibe un paquete cifrado
                logger.debug(
                    f"Received from Satellite (channel {channel}, timestamp {timestamp}): {encoded}"
                )

                # Agregar el paquete a la cola para decodificarlo
                self.to_decode.put_nowait(encoded)

                # Debug: confirmar que el paquete se agregó a la cola
                logger.debug(f"Packet enqueued for decoding: {encoded}")

        except ConnectionRefusedError:
            logger.critical(f"Could not connect to Satellite at {self.sat_host}:{self.sat_port}")
            self.crash.set()
        except Exception as e:
            logger.critical(f"Downlink error: {e}")
            self.crash.set()
            raise

    def decode(self):
        """Serve frames from the queue to the Decoder, printing the decoded results"""
        logger.info("Starting decoding process...")

        try:
            logger.debug(f"Funcionando")
            while not self.crash.is_set():
                queue_size = self.to_decode.qsize()
                logger.debug(f"Tamaño del queue: {queue_size}")
                if not self.to_decode.empty():
                    encoded = self.to_decode.get_nowait()
                    logger.debug(f"Extracted packet from queue: {encoded}")

                    try:
                        decoded = self.decoder.decode(encoded)
                        if decoded:
                            logger.debug(f"Decoder response: {decoded}")
                            logger.info(f"Decoded output: {decoded}")
                        else:
                            logger.error("Decoder did not return any data.")
                    except Exception as e:
                        logger.error(f"Error during decoder.decode(): {e}")

        except Exception as e:
            logger.critical(f"Decoder error: {e}")
            self.crash.set()
            raise

    def run(self):
        """Run the TV, connecting to the Satellite and the Decoder"""
        try:
            decode_thread = threading.Thread(target=self.decode)
            decode_thread.start()
            downlink_thread = threading.Thread(target=self.downlink, daemon=True)
            downlink_thread.start()
            while downlink_thread.is_alive() and decode_thread.is_alive():
                # El hilo principal duerme para evitar usar excesivamente la CPU
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        finally:
            self.crash.set()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="ectf25.tv",
        description="Run the TV, pulling frames from the satellite, decoding using "
                    "the Decoder, and printing to the terminal",
    )
    parser.add_argument("sat_host", help="TCP host of the satellite")
    parser.add_argument("sat_port", type=int, help="TCP port of the satellite")
    parser.add_argument(
        "dec_port",
        help="Serial port to the Decoder (see https://rules.ectf.mitre.org/2025/getting_started/boot_reference for platform-specific instructions)",
    )
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate of the serial port")
    args = parser.parse_args()

    tv = TV(args.sat_host, args.sat_port, args.dec_port, args.baud)
    tv.run()


if __name__ == "__main__":
    main()
