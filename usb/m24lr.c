#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <libusb.h>

#include "m24lr.h"
#include "cr95hf.h"

unsigned char UID[] = {0x60, 0x63, 0xcd, 0xb9, 0x9a, 0x58, 0x2, 0xe0};
unsigned char request[CR95HF_BUFFER_SIZE] = {0};
unsigned char response[CR95HF_BUFFER_SIZE] = {0};

int m24lr_inventory(unsigned char *uid)
{
	int i,r=0;
	
	if(uid == NULL) return M24LR_PARAMETER_ERROR;
	
	request[0] = M24LR_FLAG_INVENTORY | M24LR_FLAG_DATARATE_H | M24LR_FLAG_1_SLOT; // flags
	request[1] = M24LR_INVENTORY; // Inventory
	request[2] = 0x00; // Mask

	do {
		r = cr95hf_sendrecv(request, 3, response, CR95HF_BUFFER_SIZE); 
		printf("Waiting for tag\n");
		usleep(50000);
	} while(m24lr_error(response));
	
	memcpy(uid, &response[5], M24LR_UID_SIZE);
	
	return response[4]; // return DSFID
}

int m24lr_get_system_info(unsigned char *uid, M24LR_system_info *system_info)
{
	int i,r=0;
	
	if(system_info == NULL) return M24LR_PARAMETER_ERROR;
	
	request[0] = M24LR_FLAG_DATARATE_H; // flags		
	request[1] = M24LR_GET_SYSTEM_INFO;	

	memset(response, 0, CR95HF_BUFFER_SIZE);
	if(uid)
	{
		memcpy(&request[2], uid, M24LR_UID_SIZE);
		request[0] |= M24LR_FLAG_ADDRESS;
		r = cr95hf_sendrecv(request, 10, response, CR95HF_BUFFER_SIZE); 		
	} else {
		r = cr95hf_sendrecv(request, 2, response, CR95HF_BUFFER_SIZE); 		
	}
	
	r = m24lr_error(response);
	if(r) return r;
	
	system_info->information_flags=response[4];
	memcpy(&system_info->UID[0], &response[5], M24LR_UID_SIZE);
	system_info->DSFID=response[13];
	system_info->AFI=response[14];
	system_info->memory_size=response[16]<<8;
	system_info->memory_size+=response[15];
	system_info->IC_ref=response[17];
	return 0;
	
}

int m24lr_read_block(unsigned char address, unsigned int *block)
{
	int i,r=0;
	
	request[0] = M24LR_FLAG_DATARATE_H;// | M24LR_FLAG_ADDRESS; // flags		
	request[1] = M24LR_READ_SINGLE_BLOCK; // Read block
	request[2] = address; // Block number
	
	//memcpy(&request[2], UID, sizeof(UID));				
	
	memset(response, 0, CR95HF_BUFFER_SIZE);
	r = cr95hf_sendrecv(request, 3, response, CR95HF_BUFFER_SIZE); 
	
	r = m24lr_error(response);
	if(r) return r;
	
	*block = 0;
	for(i = 4; i<8; i++)
	{
		*block = (*block<<8) + response[i];
		printf("%c", response[i], *block);
	}
	return 0;
}

int m24lr_write_block(unsigned char address, unsigned int block)
{
	int i,r=0;
	
	request[0] = M24LR_FLAG_DATARATE_H;// flags		
	request[1] = M24LR_WRITE_SINGLE_BLOCK; // Write block
	request[2] = address; // Block number
	request[3] = (block>>24)&0xff;
	request[4] = (block>>16)&0xff;
	request[5] = (block>>8)&0xff;
	request[6] = (block>>0)&0xff;
	
	memset(response, 0, CR95HF_BUFFER_SIZE);
	
	cr95hf_sendrecv(request, 7, response, CR95HF_BUFFER_SIZE); 
	r = m24lr_error(response);
	
	return r;
}

int m24lr_read_sector(unsigned char sector, unsigned char *blocks)
{
	int i,r=0;
	
	request[0] = M24LR_FLAG_DATARATE_H;// | M24LR_FLAG_ADDRESS; // flags		
	request[1] = M24LR_READ_MULTIPLE_BLOCKS; // Read block
	request[2] = sector*32; // Block number
	request[3] = 9; // Number of blocks
	
	//memcpy(&request[2], UID, sizeof(UID));				
	
	memset(response, 0, CR95HF_BUFFER_SIZE);
	r = cr95hf_sendrecv(request, 4, response, CR95HF_BUFFER_SIZE); 
	
	r = m24lr_error(response);
	if(r) return r;
		
	for(i = 0; i<CR95HF_BUFFER_SIZE; i++)
	{	
		
		printf("%c", response[i], response[i]);
	}
	printf("\n");
	return 0;
}

int m24lr_error(unsigned char *response)
{
	if(response[0] != CR95HF_USB_OK)
	{
		// USB error
		fprintf(stderr,"USB error\n");
		exit(-1);
	}
	if(response[1] != CR95HF_OK)
	{
		// CR95HF error		
		return response[1];
	}
	
	unsigned char message_length = response[2];
	if((message_length+2)>CR95HF_BUFFER_SIZE || response[message_length+2])
	{
		// CRC error
		fprintf(stderr, "CRC error\n");
		return M24LR_CRC_ERROR;
	}
	
	if(response[3])
	{
		// m24lr error
		return response[3];
	}	
	return 0;
}