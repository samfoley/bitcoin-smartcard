// bitcoin.c
#include "asf.h"
#include "bitcoin.h"

#define TXID_LENGTH 32
#define SCRIPT_LENGTH 24
#define MIN_CONFIRMATIONS 6


#define OP_DUP 0x76
#define OP_HASH160 0xA9
#define OP_EQUALVERIFY 0x88
#define OP_CHECKSIG 0xAC
#define HASH160_LENGTH 20
#define SIG_LENGTH 32
#define PUBKEY_LENGTH 32



struct unspent
{
	uint8_t txid[32]; 
	uint8_t vout;
	uint8_t script[SCRIPT_LENGTH];
	uint8_t script_length;
	uint32_t amount;
	uint8_t confirmations;
};

struct unspent unspent_outputs[3];
int unspent_count = 0;

uint8_t change_address[HASH160_LENGTH];

uint8_t bitcoin_transaction(uint8_t address[], uint32_t amount)
{
	bitcoin_tx tx;
	int i;
	struct _tx_in tx_in[3];
	struct _tx_out tx_out[2];
	
	if(bitcoin_get_balance()<amount) return 1;

	tx.version=BITCOIN_TX_VERSION;
	tx.tx_in_count = unspent_count;
	
	
	tx.tx_in = tx_in;
	for(i=0; i<tx.tx_in_count; i++)
	{
		tx.tx_in[i].tx_id = unspent_outputs[i].txid;
		tx.tx_in[i].index = unspent_outputs[i].vout;
		tx.tx_in[i].script_length=0;
		tx.tx_in[i].scriptSig=(void*)0;
		tx.tx_in[i].sequence=BITCOIN_SEQUENCE;
	}
	
	
	tx.tx_out = tx_out;
	tx.tx_out_count = 2;
	
	// Out
	tx.tx_out[0].amount = amount;
	tx.tx_out[0].script_length = SCRIPT_PUBKEY_LENGTH;
	tx.tx_out[0].scriptPubKey[0]=OP_DUP;
	tx.tx_out[0].scriptPubKey[1]=OP_HASH160;
	tx.tx_out[0].scriptPubKey[2]=HASH160_LENGTH;
	for(i=0; i<HASH160_LENGTH; i++)
		tx.tx_out[0].scriptPubKey[3+i]=address[i];
	tx.tx_out[0].scriptPubKey[HASH160_LENGTH+3]=OP_EQUALVERIFY;
	tx.tx_out[0].scriptPubKey[HASH160_LENGTH+4]=OP_CHECKSIG;
	
	// Change
	tx.tx_out[1].amount = amount;
	tx.tx_out[1].script_length = SCRIPT_PUBKEY_LENGTH;
	tx.tx_out[1].scriptPubKey[0]=OP_DUP;
	tx.tx_out[1].scriptPubKey[1]=OP_HASH160;
	tx.tx_out[1].scriptPubKey[2]=HASH160_LENGTH;
	for(i=0; i<HASH160_LENGTH; i++)
		tx.tx_out[1].scriptPubKey[3+i]=change_address[i];
	tx.tx_out[1].scriptPubKey[HASH160_LENGTH+3]=OP_EQUALVERIFY;
	tx.tx_out[1].scriptPubKey[HASH160_LENGTH+4]=OP_CHECKSIG;
	
	tx.lock_time=BITCOIN_LOCK_TIME;
	
	return 0;
}

uint8_t bitcoin_add_unspent(uint8_t txid[], uint8_t vout, 
	uint8_t script[], uint8_t script_length, uint32_t amount,
	uint8_t confirmations)
{
	int i;
	
	if(unspent_count>2) return 1;
	if(confirmations<MIN_CONFIRMATIONS) return 2;
	
	for(i=0; i<TXID_LENGTH; i++)
		unspent_outputs[unspent_count].txid[i]=txid[i];
	unspent_outputs[unspent_count].vout=vout;
	for(i=0; i<SCRIPT_LENGTH; i++)
		unspent_outputs[unspent_count].script[i]=script[i];
	unspent_outputs[unspent_count].script_length=script_length;
	unspent_outputs[unspent_count].amount=amount;
	unspent_outputs[unspent_count].confirmations=confirmations;
	unspent_count++;
	return 0;
}

uint32_t bitcoin_get_balance()
{
	uint32_t balance = 0;
	uint8_t i;
	
	for(i=0; i<unspent_count; i++)
	{
		balance += unspent_outputs[i].amount;
	}
	return balance;
}
	