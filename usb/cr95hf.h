/*
C Driver for CR95HF contactless transceiver IC

Copyright Samuel Foley 2013
*/

#define CR95HF_VENDOR 0x0483
#define CR95HF_PRODUCT 0xd0d0
#define CR95HF_INTERFACE 1
#define CR95HF_CONFIGURATION 1
#define CR95HF_ENDPOINT_IN  0x83
#define CR95HF_ENDPOINT_OUT 0x03
#define CR95HF_MAX_COMMAND_SIZE 257
#define CR95HF_BUFFER_SIZE 64

#define CR95HF_CMD 1

#define CR95HF_IDN 				0x01
#define CR95HF_PROTOCOL_SELECT 	0x02
#define CR95HF_SEND_RECV 		0x04		
#define CR95HF_IDLE 			0x07
#define CR95HF_RDREG 			0x08
#define CR95HF_WDREG 			0x09
#define CR95HF_BAUD_RATE 		0x0A
#define CR95HF_ECHO 			0x55

#define CR95HF_OK	0x80
#define CR95HF_USB_OK 0x7

typedef unsigned char byte;
int cr95hf_init(libusb_device *dev);
int cr95hf_send_eof();
int cr95hf_sendrecv(byte *send, byte send_len, byte *recv_buffer, byte recv_len);
int cr95hf_idle();

void cr95hf_close();
void cr95hf_error(int error_code);