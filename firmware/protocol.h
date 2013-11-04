/*
 * protocol.h
 *
 * Created: 29/08/2013 6:39:33 PM
 *  Author: Sam
 */ 


#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#define STATUS_OFFSET		0x00
#define RETURN_CODE_OFFSET	0x01
#define DIGEST_OFFSET		0x04
#define R_OFFSET			0x24
#define S_OFFSET			0x44

#define DIGEST_LENGTH		0x20
#define R_LENGTH		0x20
#define S_LENGTH		0x20

#define STATUS_READY		0x1
#define STATUS_BUSY			0x2
#define STATUS_TX_WAITING	0x3
#define STATUS_TX_IN_PROGRESS		0x4
#define STATUS_TX_COMPLETE		0x5


#endif /* PROTOCOL_H_ */