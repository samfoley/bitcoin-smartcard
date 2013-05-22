all: usb test

test:	test.c
	gcc -o test test.c -lssl
	
usb: usb.c cr95hf.h cr95hf.o m24lr.o base58.o
	gcc -o usb usb.c cr95hf.o m24lr.o base58.o -I /usr/local/lib/libusb-1.0.9/libusb/ -l usb-1.0

cr95hf.o:	cr95hf.c cr95hf.h
	gcc -c cr95hf.c -I /usr/local/lib/libusb-1.0.9/libusb/
	
m24lr.o:	m24lr.c m24lr.h cr95hf.h	
	gcc -c m24lr.c -I /usr/local/lib/libusb-1.0.9/libusb/

base58.o:	base58.h base58.c
	gcc -c base58.c
	