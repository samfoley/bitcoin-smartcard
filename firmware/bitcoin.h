// bitcoin.h

#ifndef __BITCOIN_H
#define __BITCOIN_H

#define BITCOIN_TX_VERSION 1
#define BITCOIN_LOCK_TIME 0
#define BITCOIN_SEQUENCE 0xFFFFFFFF

#define SCRIPT_PUBKEY_LENGTH 25

typedef struct _tx
{
	uint32_t version;
	uint8_t tx_in_count;
	struct _tx_in *tx_in;
	uint8_t tx_out_count;
	struct _tx_out *tx_out;
	uint32_t lock_time;
} bitcoin_tx;

struct _tx_in
{
	uint8_t *tx_id;
	uint32_t index;
	uint8_t script_length;
	uint8_t *scriptSig;
	uint32_t sequence;
};

struct _tx_out
{
	int32_t amount;
	uint8_t script_length;
	uint8_t scriptPubKey[SCRIPT_PUBKEY_LENGTH];
};

uint8_t bitcoin_transaction(uint8_t address[], uint32_t amount);
uint8_t bitcoin_add_unspent(uint8_t txid[], uint8_t vout, 
	uint8_t script[], uint8_t script_length, uint32_t amount,
	uint8_t confirmations);
uint32_t bitcoin_get_balance(void);
	

#endif