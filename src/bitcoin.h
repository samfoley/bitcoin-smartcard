// bitcoin.h

#ifndef __BITCOIN_H
#define __BITCOIN_H

#define BITCOIN_TX_VERSION 1
#define BITCOIN_LOCK_TIME 0
#define BITCOIN_SEQUENCE 0xFFFFFFFF
#define BITCOIN_TRANSACTION_FEE 5000000
#define BITCOIN_TXID_LENGTH 32
#define BITCOIN_SIGHASH_ALL 1


typedef struct _tx
{
	uint32_t version;
	uint8_t tx_in_count;
	struct tx_in *tx_in;
	uint8_t tx_out_count;
	struct tx_out *tx_out;
	uint32_t lock_time;
} bitcoin_tx;

struct tx_in
{
	uint8_t *tx_id;
	uint32_t index;
	uint8_t script_length;
	uint8_t *script;
	uint32_t sequence;
};

struct tx_out
{
	int64_t amount;
	uint8_t script_length;
	uint8_t *script;
};

uint8_t bitcoin_transaction(uint8_t address[], uint64_t amount);
uint8_t bitcoin_add_unspent(uint8_t txid[], uint8_t vout, 
	uint8_t script[], uint8_t script_length, uint64_t ammount,
	uint8_t confirmations);
	
void bitcoin_sign_input(bitcoin_tx *tx,  uint8_t index);	
uint16_t bitcoin_serialize(uint8_t *tx_serialized, bitcoin_tx *tx);

#endif