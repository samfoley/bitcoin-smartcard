#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#include <libusb.h>

#include "m24lr.h"
#include "cr95hf.h"



int main(void)
{
	libusb_device **devs;
	libusb_device *dev, *cr95hf = NULL;
	
	int r,i=0;
	ssize_t cnt;
	
	r = libusb_init(NULL);
	if (r<0)
		return r;
		
	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt<0)
		return (int) cnt;
		
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
		unsigned char UID[M24LR_UID_SIZE];
		
		r = cr95hf_init(cr95hf);
		if(r) return r;
		
		//cr95hf_idle();
				
		m24lr_inventory(UID);
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
		r = m24lr_write_block(3, 0x66677071);
		if(r)
		{
			fprintf(stderr, "write block error %x\n", r);
		}
		
		unsigned int block;
		printf("\nRead block: \n");
		r = m24lr_read_block(0, &block);
		r = m24lr_read_block(1, &block);
		r = m24lr_read_block(2, &block);
		r = m24lr_read_block(3, &block);
		r = m24lr_read_block(4, &block);
		r = m24lr_read_block(5, &block);
		r = m24lr_read_block(6, &block);
		r = m24lr_read_block(7, &block);
		r = m24lr_read_block(8, &block);
		r = m24lr_read_block(9, &block);
		r = m24lr_read_block(10, &block);
		r = m24lr_read_block(11, &block);
		r = m24lr_read_block(12, &block);
		r = m24lr_read_block(13, &block);
		r = m24lr_read_block(14, &block);
		r = m24lr_read_block(15, &block);
		r = m24lr_read_block(16, &block);
		printf("\nRead multiple blocks:\n");
		unsigned char sector[32];
		r = m24lr_read_sector(0, sector);		
		if(r)
			fprintf(stderr, "sector error %d\n", r);
			
		
		
	}
	
	libusb_free_device_list(devs, 1);
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
	