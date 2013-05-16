all: usb

usb: usb.c cr95hf.h cr95hf.o m24lr.o
	gcc -o usb usb.c cr95hf.o m24lr.o -I /usr/local/lib/libusb-1.0.9/libusb/ -l usb-1.0

cr95hf.o:	cr95hf.c cr95hf.h
	gcc -c cr95hf.c -I /usr/local/lib/libusb-1.0.9/libusb/
	
m24lr.o:	m24lr.c m24lr.h cr95hf.h	
	gcc -c m24lr.c -I /usr/local/lib/libusb-1.0.9/libusb/