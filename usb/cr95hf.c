/*
C Driver for CR95HF contactless transceiver IC

Copyright Samuel Foley 2013
*/
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <libusb.h>

#include "cr95hf.h"

libusb_device_handle *handle = NULL;

int cr95hf_init(libusb_device *cr95hf)
{
	int r, i, attached = 0;	
	
	r = libusb_open(cr95hf, &handle);
	if(r) cr95hf_error(r);
	
	if ( libusb_kernel_driver_active(handle, CR95HF_INTERFACE) ){ 
		printf("Device busy...detaching...\n"); 
		libusb_detach_kernel_driver(handle, CR95HF_INTERFACE); 
		attached = 1;
	}else printf("Device free from kernel\n"); 

	r = libusb_set_configuration( handle, CR95HF_CONFIGURATION );
	
	if(r) cr95hf_error(r);
	
	r = libusb_claim_interface( handle, CR95HF_INTERFACE );
	if (r){
		fprintf(stderr, "Failed to claim interface. " );
		cr95hf_error(r);
	}
	
	r = libusb_reset_device(handle);
	if(r) cr95hf_error(r);
	
	unsigned char output_buffer[CR95HF_BUFFER_SIZE];
	unsigned char input_buffer[CR95HF_BUFFER_SIZE];
	memset(output_buffer, 0, CR95HF_BUFFER_SIZE);
	memset(input_buffer, 0, CR95HF_BUFFER_SIZE);
	
	output_buffer[0] = CR95HF_CMD; // CR95HF Command Mode
	output_buffer[1] = CR95HF_PROTOCOL_SELECT; // Protocol select command
	output_buffer[2] = 0x02; // Command length 2
	output_buffer[3] = 0x01;  // Protocol ISO15093
	output_buffer[4] = 0x0D; // Parameters modulation=10%
	int transferred = 0;
			
	r = libusb_interrupt_transfer(handle, CR95HF_ENDPOINT_OUT, output_buffer, CR95HF_BUFFER_SIZE, &transferred, 500);
	if(r) {
		fprintf(stderr, "output error ");
		cr95hf_error(r);
	}
	if(transferred!=CR95HF_BUFFER_SIZE)
	{
		fprintf(stderr, "transferred=%d\n", transferred);
		exit(-1);
	}
	transferred=0;
	r = libusb_interrupt_transfer	(handle, CR95HF_ENDPOINT_IN, input_buffer, 64, &transferred, 500);
	if(r) {
		fprintf(stderr, "output error ");
		cr95hf_error(r);
	}
	if(transferred>0) 
	{
		printf("received %d\n", transferred);		
	} else {
		fprintf(stderr,"transferred %d\n", transferred);
	}
	
	
	return 0;
}

int cr95hf_send_eof()
{
	int r, transferred;
	unsigned char output_buffer[CR95HF_BUFFER_SIZE];	
	memset(output_buffer, 0, CR95HF_BUFFER_SIZE);
	
	output_buffer[0] = CR95HF_CMD;
	output_buffer[1] = CR95HF_SEND_RECV;
	output_buffer[2] = 0;
	
	r = libusb_interrupt_transfer(handle, CR95HF_ENDPOINT_OUT, output_buffer, CR95HF_BUFFER_SIZE, &transferred, 500);
	if(r) {
		fprintf(stderr, "send_eof output error ");
		cr95hf_error(r);
	}
	return transferred;
}
int cr95hf_sendrecv(byte *send, byte send_len, byte *recv_buffer, byte recv_len)
{
	unsigned char output_buffer[CR95HF_BUFFER_SIZE];
	unsigned char input_buffer[CR95HF_BUFFER_SIZE];
	memset(output_buffer, 0, CR95HF_BUFFER_SIZE);
	memset(input_buffer, 0, CR95HF_BUFFER_SIZE);
	int i, r;
	int transferred=0;
	
	output_buffer[0] = CR95HF_CMD;
	output_buffer[1] = CR95HF_SEND_RECV;
	output_buffer[2] = send_len;
	for(i=0; i<send_len; i++)
		output_buffer[3+i]=send[i];
	
	r = libusb_interrupt_transfer(handle, CR95HF_ENDPOINT_OUT, output_buffer, CR95HF_BUFFER_SIZE, &transferred, 500);
	if(r) {
		fprintf(stderr, "sendresv output error ");
		cr95hf_error(r);
	}
	if(transferred!=CR95HF_BUFFER_SIZE)
	{
		fprintf(stderr,"sendrecv transferrred %d\n", transferred);
		exit(-1);
	}	
	
	r = libusb_interrupt_transfer(handle, CR95HF_ENDPOINT_IN, recv_buffer, recv_len, &transferred, 500);
	if(r) {
		fprintf(stderr, "sendresv input error ");
		cr95hf_error(r);
	}
	
	return transferred;
}

int cr95hf_idle()
{
	unsigned char output_buffer[CR95HF_BUFFER_SIZE];
	unsigned char input_buffer[CR95HF_BUFFER_SIZE];
	int r, transferred = 0;
	
	memset(output_buffer, 0, CR95HF_BUFFER_SIZE);
	
	output_buffer[0] = CR95HF_CMD;
	output_buffer[1] = CR95HF_IDLE;
	output_buffer[2] = 0x0E;	
	output_buffer[3] = 0x0A;
	output_buffer[4] = 0x21;
	output_buffer[5] = 0x00;
	output_buffer[6] = 0x79;
	output_buffer[7] = 0x01;
	output_buffer[8] = 0x18;
	output_buffer[9] = 0x00;
	output_buffer[0xA] = 0x20;
	output_buffer[0xB] = 0x60;
	output_buffer[0xC] = 0x60;
	output_buffer[0xD] = 0x64;	
	output_buffer[0xF] = 0x74;
	output_buffer[0x10] = 0x3f;
	output_buffer[0x11] = 0x08;
	
	r = libusb_interrupt_transfer(handle, CR95HF_ENDPOINT_OUT, output_buffer, CR95HF_BUFFER_SIZE, &transferred, 500);
	if(r) {
		fprintf(stderr, "idle output error ");
		cr95hf_error(r);
	}
	if(transferred!=CR95HF_BUFFER_SIZE)
	{
		fprintf(stderr,"sendrecv transferrred %d\n", transferred);
		exit(-1);
	}	
	
	r = libusb_interrupt_transfer(handle, CR95HF_ENDPOINT_IN, input_buffer, CR95HF_BUFFER_SIZE, &transferred, 500);
	if(r) {
		fprintf(stderr, "idle input error ");
		cr95hf_error(r);
	}
	
	printf("idle repsonse %x\n", input_buffer[1]);
	
}
void cr95hf_close()
{
	if(handle)
	{
		libusb_release_interface(handle, CR95HF_INTERFACE);
		libusb_attach_kernel_driver(handle, CR95HF_INTERFACE);
		libusb_close(handle);
		handle=NULL;
	}
}

void cr95hf_error(int error_code)
{
	const char *error = libusb_error_name(error_code);
	fprintf(stderr, "%s\n", error);
	exit(error_code);
}