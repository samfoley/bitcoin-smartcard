#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <libusb.h>

#include "m24lr.h"
#include "cr95hf.h"
#include "base58.h"
#include "protocol.h"

#define BITCOIN_TRANSACTION_READY 0x01
#define BITCOIN_UNSPENT_READY 0x02
#define BITCOIN_PENDING 0x20
#define BITCOIN_COMPLETE 0x30

#define MAX_RETRIES 5
#define RETRY_DELAY 10000

const char bitcoin_address[] = "mwwdpwLoVr7BsCRyPqwyCCPGS93JenAZRS";
int bitcoin_satoshis = 100000000;

void start_tx(uint8_t *hash);
int write_tx(uint8_t *hash);
int read_tx(void);

uint8_t parse_hex(char hex);

int set_status(uint8_t status);

uint8_t parse_hex(char hex)
{
	hex = tolower(hex);
	switch(hex) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			return hex-'0';			
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
			return 0x0a + hex-'a';			
	}	
	return 0x10; // ERROR
}

int main(int argc, char *argv[])
{
	libusb_device **devs = NULL;
	libusb_device *dev = NULL, *cr95hf = NULL;
	uint8_t hash[DIGEST_LENGTH];
	
	int r,i=0;
	ssize_t cnt;
	
	if(argc == 2 && strlen(argv[1])==64)
	{		
		for(i=0; i<DIGEST_LENGTH; i++)
		{
			r = parse_hex(argv[1][i*2]);
			
			if(r>0x0f){
				fprintf(stderr, "Invalid arguments\nusb <32bytehash>\n");
				exit(1);
			}
			hash[i] = r<<4;
			r = parse_hex(argv[1][i*2+1]);
			if(r>0x0f){
				fprintf(stderr, "Invalid arguments\nusb <32bytehash>\n");
				exit(1);
			}
			hash[i] += r;			
		}	
	} else {
		fprintf(stderr, "Invalid arguments\nusb <32bytehash>\n");
		exit(1);
	}
	
	r = libusb_init(NULL);
	if (r<0)
		return r;
		
	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt<0)
		return (int) cnt;
	
	i=0;	
	while ((dev	= devs[i++]) != NULL) {
		struct libusb_device_descriptor desc;
		r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0) {
			fprintf(stderr, "failed to get device descriptor");
			return r;
		}
		if(desc.idVendor == CR95HF_VENDOR && desc.idProduct == CR95HF_PRODUCT)
			cr95hf = dev;
	}
	
	if(cr95hf == NULL)
	{
		fprintf(stderr, "CR95HF not found");
		return -1;
	} 
	else
	{
		
		
		r = cr95hf_init(cr95hf);
		if(r) return r;
		
		start_tx(hash);				
	}
	
	libusb_free_device_list(devs, 1);
}

void start_tx(uint8_t *hash)
{
	int errors, r,i=0;
	unsigned char UID[M24LR_UID_SIZE];
	uint32_t block;
	
	m24lr_inventory(UID);
	usleep(100000);
	printf("UID ");
	for(i=0;i<M24LR_UID_SIZE; i++)
			printf("%02x", UID[i]);
	printf("\n");
	
	
	printf("\nGet system info: \n");
	M24LR_system_info info;
	r = m24lr_get_system_info(UID, &info);
	while(r)
	{
		usleep(10000);
		printf("retrying\n");
		r = m24lr_get_system_info(NULL, &info);
	}
		
	if(r)
		printf("get system info error %d\n", r);
	else 
	{
		printf("flags %x DSFID %x AFI %x Memory size %x IC Ref %x UID ",
			info.information_flags, info.DSFID, info.AFI,
			info.memory_size, info.IC_ref);
		for(i=0;i<M24LR_UID_SIZE; i++)
			printf("%02x", info.UID[i]);
		printf("\n");
	}
	
	
	printf("\nWaiting for response\n");
	errors=0;
	while(1)
	{
		r = m24lr_read_block(0, &block);
		if(r)
		{
			if(errors>20) start_tx(hash);
			errors++;
			
			switch(r)
			{
				case 0x86:
					printf("Communications error\n"); break;
				case 0x87:
					printf("Frame timeout error\n"); errors--; break;
				case 0x88:
					printf("Invalid SOF error\n"); errors--; break;
				case 0x89:
					printf("Buffer overflow error\n"); break;
				default:
					printf("0x%02x error\n", r);
			}
		} else {
			errors=0;
			switch(block>>24)
			{
				case STATUS_READY:
					printf("Ready\n"); 
					r = write_tx(hash);
					if(r){
						set_status(STATUS_READY);
						printf("write_tx error %02x\n", r);
					}
					break;
				case STATUS_BUSY:
					printf("Busy\n"); 
					set_status(STATUS_READY);
					break;
				case STATUS_TX_WAITING:
					printf("Transaction pending\n"); break;
				case STATUS_TX_IN_PROGRESS:
					printf("Transaction in progress\n"); break;
				case STATUS_TX_COMPLETE:
					printf("Transaction complete\n"); 
					r = read_tx();
					printf("read_tx error %02x\n", r);
					break;
				default:
					printf("Unknown response %08x\n", block); break;
			}
		}
		fflush(stdout);
		
		usleep(100000);
	}
	
	printf("\nReading address\n");
	for(i=0; i<7; i++)
	{
		if(m24lr_read_block(3+i, &block))
		{
			printf("____");
		} else {
			printf("%04x", block);
		}
	}
	printf("\n");
}

int set_status(uint8_t status)
{
	uint32_t block;
	int r, errors = 0;
	while(r = m24lr_read_block(0, &block))
	{
		if(errors > MAX_RETRIES) return r;
		errors++;
		usleep(RETRY_DELAY);
	}
	block = (status<<24) | (block&0x00ffffff);
	errors=0;
	while(r = m24lr_write_block(0, block))
	{
		if(errors > MAX_RETRIES) return r;
		errors++;
		usleep(RETRY_DELAY);
	}
	return 0;
}


int write_tx(uint8_t *hash)
{
	int i,r,errors=0;
	
	uint32_t block;
	
	r = set_status(STATUS_BUSY);
	if(r) return r;
	
	for(i=0; i<DIGEST_LENGTH/4; i++)
	{
		block =
			hash[i*4+0] << 24 |
			hash[i*4+1] << 16 |
			hash[i*4+2] << 8 |
			hash[i*4+3] << 0;
			
		while(r = m24lr_write_block(i + DIGEST_OFFSET/4, block))
		{
			if(errors > MAX_RETRIES) return r;
			errors++;
			usleep(RETRY_DELAY);
		}
		errors=0;
	}
	set_status(STATUS_TX_WAITING);
	return 0;
}

int read_tx(void)
{
	int i,r,errors=0;
	uint32_t block;
	
	printf("Transaction Signature:\n");
	
	printf("r: ");
	for(i=0; i<R_LENGTH/4; i++)
	{
		errors=0;
		while(r = m24lr_read_block(i + R_OFFSET/4, &block))
		{
			if(errors > MAX_RETRIES) return r;
			errors++;
			usleep(RETRY_DELAY);
		}
		
		printf("%08x", block);
	}
	printf("\ns: ");
	for(i=0; i<S_LENGTH/4; i++)
	{
		errors=0;
		while(r = m24lr_read_block(i + S_OFFSET/4, &block))
		{
			if(errors > MAX_RETRIES) return r;
			errors++;
			usleep(RETRY_DELAY);
		}
		
		printf("%08x", block);
	}
	printf("\n");
	set_status(STATUS_READY);
	exit(0);
}

#define POLYNOMIAL 0x8408// x^16 + x^12 + x^5 + 1
#define PRESET_VALUE 0xFFFF
#define CHECK_VALUE 0xF0B8
#define NUMBER_OF_BYTES 4// Example: 4 data bytes
#define CALC_CRC1
#define CHECK_CRC0

unsigned short crc16(unsigned char *data_p, unsigned short length)
{
	unsigned short current_crc_value;	
		
	int number_of_databytes = NUMBER_OF_BYTES;
	
	int i, j;
	
	current_crc_value = PRESET_VALUE;
	for (i = 0; i < length; i++)
	{
		current_crc_value = current_crc_value ^ ((unsigned short)data_p[i]);
	
		for (j = 0; j < 8; j++)
		{
			if (current_crc_value & 0x0001)
			{
				current_crc_value = (current_crc_value >> 1) ^
				POLYNOMIAL;
			}
			else
			{
				current_crc_value = (current_crc_value >> 1);
			}
		}
	}
	current_crc_value = ~current_crc_value;

	return current_crc_value;
		// current_crc_value is now ready to be appended to the data stream
		// (first LSByte, then MSByte)		
}
	