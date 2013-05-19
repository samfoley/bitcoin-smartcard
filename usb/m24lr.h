#define M24LR_INVENTORY 0x01
#define M24LR_READ_SINGLE_BLOCK 0x20
#define M24LR_WRITE_SINGLE_BLOCK 0x21
#define M24LR_READ_MULTIPLE_BLOCKS 0x23
#define M24LR_GET_SYSTEM_INFO 0x2B
#define M24LR_READ_CFG 0xA0 
#define M24LR_WRITE_EHFG 0xA1
#define M24LR_WRITE_DOCFG 0xA4

#define M24LR_FLAG_SUBCARRIER 1
#define M24LR_FLAG_DATARATE_H 2
#define M24LR_FLAG_INVENTORY 4
#define M24LR_FLAG_PROTOCOL_EXTENSION 8

#define M24LR_FLAG_SELECT 0x10
#define M24LR_FLAG_ADDRESS 0x20
#define M24LR_FLAG_OPTION 0x40

#define M24LR_FLAG_AFI 0x10
#define M24LR_FLAG_1_SLOT 0x20

#define M24LR_FLAGS M24LR_FLAG_DATARATE_H

#define M24LR_OK 0x80
#define M24LR_PARAMETER_ERROR -1
#define M24LR_CRC_ERROR -2
#define M24LR_UID_SIZE 8
#define M24LR_IC_MFG 0x02
#define M24LR_CFG_WIP 0x08
#define M24LR_CFG_RF_BUSY 0

typedef struct _m24lr_system_info
{
	unsigned char information_flags;
	unsigned char UID[M24LR_UID_SIZE];
	unsigned char DSFID;
	unsigned char AFI;
	unsigned short memory_size;
	unsigned char IC_ref;
} M24LR_system_info;

unsigned short crc16(unsigned char *data_p, unsigned short length);

int m24lr_inventory(unsigned char *uid);
int m24lr_get_system_info(unsigned char *uid, M24LR_system_info *system_info);
int m24lr_read_block(unsigned char address, unsigned int *block);
int m24lr_write_block(unsigned char address, unsigned int block);
int m24lr_read_sector(unsigned char sector, unsigned char *blocks);
int m24lr_read_config(unsigned char *config);
int m24lr_write_docfg(unsigned char data);

int m24lr_error(unsigned char *response);