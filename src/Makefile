all: usb test bitcoin bignum32

test:	test.c base58.h base58.o bignum8.o ecdsa.o bn8_misc.o
	gcc -o test test.c base58.o bignum8.o ecdsa.o bn8_misc.o -lssl -pg -g
	
usb: usb.c cr95hf.h cr95hf.o m24lr.o base58.o
	gcc -o usb usb.c cr95hf.o m24lr.o base58.o -I /usr/local/lib/libusb-1.0.9/libusb/ -l usb-1.0

bitcoin: bitcoin.c bitcoin.h ecdsa.o bignum8.o bn8_misc.o
	gcc -o bitcoin bitcoin.c ecdsa.o bignum8.o bn8_misc.o -lssl -pg -g
	
cr95hf.o:	cr95hf.c cr95hf.h
	gcc -c cr95hf.c -I /usr/local/lib/libusb-1.0.9/libusb/
	
m24lr.o:	m24lr.c m24lr.h cr95hf.h	
	gcc -c m24lr.c -I /usr/local/lib/libusb-1.0.9/libusb/

base58.o:	base58.h base58.c
	gcc -c base58.c

bignum8.o:	bignum8.c bignum8.h
	gcc -c bignum8.c -pg -g

bignum32.o: bignum32.c bignum32.h bn8_misc.h
	gcc -c bignum32.c -g
	
bignum32: bignum32.o
	gcc -o bignum32 bignum32.o -g
	
ecdsa.o:	ecdsa.c ecdsa.h bignum8.h
	gcc -c ecdsa.c -pg -g
	
bn8_misc.o: bn8_misc.c bn8_misc.h bignum8.h
	gcc -c bn8_misc.c
	
clean:
	rm *.o
	