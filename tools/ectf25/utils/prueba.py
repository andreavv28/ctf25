from serial import Serial

ser = Serial('/dev/ttyACM0', baudrate=115200, timeout=1)
ser.write(b"%D\x00\x00")  # Enviar un comando de prueba
response = ser.read(100)  # Leer respuesta
print(response)
ser.close()
