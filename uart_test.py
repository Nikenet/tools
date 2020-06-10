import serial
import time
import string
import random

port     = '/dev/ttyUSB0' # device
length   = 2048           # string length
depth    = 10             # count of iteration
baudrate = [9600,    14400,   19200,   28800,   38400, 
            57600,   114200,  230400,  460800,  500000,  
            576000,  921600,  1000000, 1152000, 1500000,
            2000000, 2500000, 3000000, 3500000]

class colors:
	HEADER    = '\033[95m'
	OKBLUE    = '\033[94m'
	OKGREEN   = '\033[92m'
	WARNING   = '\033[93m'
	FAIL      = '\033[91m'
	ENDC      = '\033[0m'
	BOLD      = '\033[1m'
	UNDERLINE = '\033[4m'

def randomString(stringLength=8):
	letters = string.hexdigits
	return ''.join(random.choice(letters) for i in range(stringLength))

def test(serial_port):

	for i in range(depth):
		tx = randomString(length)
		serial_port.write(str.encode(tx))
		time.sleep(1)
		rx = serial_port.readline().decode()
		if tx != rx:
			return 1
	return 0

try:
	for i in range(19):
		baud = baudrate[i]
		print('Baudrate {:7d}'.format(baud), end=' ')
		serial_port = serial.Serial(port, baud, timeout=0)
		if test(serial_port) == 0:
			print(colors.OKGREEN + "SUCCESS" + colors.ENDC)
		else:
			print(colors.WARNING + "FAILURE" + colors.ENDC)
		serial_port.flushInput()

except KeyboardInterrupt:
	print(colors.FAIL + "\nIterrupted" + colors.ENDC)
