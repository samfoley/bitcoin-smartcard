#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>

#include "bitcoin.h"
#include "bignum32.h"
#include "ecdsa.h"

uint8_t to_address[200] = {0xb4, 0x2c, 0xfe, 0xe4, 0x7e, 0x6c, 0xaf, 0xb6, 0x7c, 0xff, 0x40, 0x6a, 0xb7, 0x8c, 0x7d, 0xa4, 0xd0, 0x55, 0x9f, 0x35};
uint8_t change_address[200] = {0x49, 0x4f, 0xcf, 0x55, 0xac, 0x4e, 0xfb, 0x77, 0xd2, 0x09, 0x85, 0x32, 0x51, 0x2f, 0x42, 0x8e, 0x25, 0x9f, 0x63, 0x42};
uint64_t amount =   100000000; // 1 btc = 10e8 satoshis
uint64_t balance  = 400000000; // current wallet balance

uint8_t in1_tx_id[200] = {0x53, 0xd9, 0xd9, 0xdc, 0x25, 0xbd, 0x04, 0x92, 0x8c, 0xfe, 0xd1, 0x07, 0x0d, 0x51, 0x0e, 0xcc, 0xb3, 0x46, 0xe3, 0xa8, 0xb3, 0xaa, 0x8d, 0xaf, 0x21, 0x7a, 0xe4, 0xd1, 0x29, 0x36, 0x31, 0xcc};
uint8_t in1_script[225] = {0x76, 0xa9, 0x14, 0x49, 0x4f, 0xcf, 0x55, 0xac, 0x4e, 0xfb, 0x77, 0xd2, 0x09, 0x85, 0x32, 0x51, 0x2f, 0x42, 0x8e, 0x25, 0x9f, 0x63, 0x42, 0x88, 0xac};

uint8_t in2_tx_id[200] = {0xe8, 0x0c, 0x2f, 0x8a, 0x6c, 0x6d, 0x1d, 0xcf, 0x8c, 0x26, 0xa4, 0x72, 0x92, 0x58, 0x5b, 0xd3, 0x55, 0x95, 0x4e, 0xd2, 0xaa, 0x39, 0xcc, 0x20, 0xbd, 0x4f, 0xa1, 0xfe, 0x3f, 0x8c, 0xf2, 0x6b};
uint8_t in2_script[225] = {0x76, 0xa9, 0x14, 0x49, 0x4f, 0xcf, 0x55, 0xac, 0x4e, 0xfb, 0x77, 0xd2, 0x09, 0x85, 0x32, 0x51, 0x2f, 0x42, 0x8e, 0x25, 0x9f, 0x63, 0x42, 0x88, 0xac};

uint8_t public_key[32] = {0x39, 0xA1, 0xE5, 0x74, 0xB4, 0x75, 0xBE, 0x52, 0x04, 0xF7, 0x8C, 0xB3, 0x72, 0x85, 0x4B, 0x4C, 0x85, 0x82, 0x20, 0xBD, 0xE4, 0x92, 0x09, 0x6C, 0x3A, 0xF1, 0xC5, 0xF1, 0xB6, 0x94, 0x4B, 0xC1};


void write32(uint8_t *buffer, uint32_t data);
void write64(uint8_t *buffer, uint64_t data);

int main()
{
	uint16_t i;
	uint16_t length;
	uint8_t *out;
	uint8_t buffer[1000];
	bitcoin_tx transaction;
	struct tx_in transaction_inputs[2];
	struct tx_out transaction_outputs[2];
	
	// build tx
	transaction.version = BITCOIN_TX_VERSION;
	transaction.lock_time = BITCOIN_LOCK_TIME;

	// build txin
	transaction.tx_in_count = 2;
	transaction.tx_in= transaction_inputs;
	
	transaction.tx_in[0].tx_id = in1_tx_id;
	transaction.tx_in[0].index = 1;
	transaction.tx_in[0].script = in1_script;
	transaction.tx_in[0].script_length = 25;
	transaction.tx_in[0].sequence = BITCOIN_SEQUENCE;
	
	transaction.tx_in[1].tx_id = in2_tx_id;
	transaction.tx_in[1].index = 0;
	transaction.tx_in[1].script = in2_script;
	transaction.tx_in[1].script_length = 25;
	transaction.tx_in[1].sequence = BITCOIN_SEQUENCE;
	
	// build txout
	transaction.tx_out_count = 2;
	transaction.tx_out = transaction_outputs;
	
	// recipient
	transaction.tx_out[0].amount = amount;
	transaction.tx_out[0].script_length = 25;
	transaction.tx_out[0].script = malloc(25);
	out = transaction.tx_out[0].script;
	out[0] = 0x76; // OP_DUP
	out[1] = 0xA9; // OP_HASH_160
	out[2] = 0x14; // Push 20 bytes
	for(i=0; i<20; i++)
	{
		out[3+i]=to_address[i];
	}
	out[23] = 0x88; // OP_EQUALVERIFY
	out[24] = 0xac; // OP_CHECKSIG
	
	// change 
	transaction.tx_out[1].amount = balance - amount - BITCOIN_TRANSACTION_FEE;
	transaction.tx_out[1].script_length = 25;
	transaction.tx_out[1].script = malloc(25);
	out = transaction.tx_out[1].script;
	out[0] = 0x76; // OP_DUP
	out[1] = 0xA9; // OP_HASH_160
	out[2] = 0x14; // Push 20 bytes
	for(i=0; i<20; i++)
	{
		out[3+i]=change_address[i];
	}
	out[23] = 0x88; // OP_EQUALVERIFY
	out[24] = 0xac; // OP_CHECKSIG
	
	// foreach txin prepare tx for signing
	for(i = 0; i<transaction.tx_in_count; i++)
	{
		bitcoin_sign_input(&transaction, i);
	}
	
	// print hex tx
	length = bitcoin_serialize(buffer, &transaction);	
	for(i=0; i<length; i++)
	{
		printf("%02x", buffer[i]);
	}
	printf("\n");
	return 0;
}

void bitcoin_sign_input(bitcoin_tx *tx,  uint8_t index)
{
	uint8_t tx_serialized[1000];
	uint16_t i = 0;
	uint8_t j = 0;
	uint8_t k = 0;
	
	uint8_t r[32];
	uint8_t s[32];
	
	// version
	write32(tx_serialized+i, tx->version); i+= 4;
	// in count
	tx_serialized[i++] = tx->tx_in_count;
	// txin
	for(j=0; j < tx->tx_in_count; j++)
	{
		// txid
		for(k=0; k < BITCOIN_TXID_LENGTH; k++)
		{
			tx_serialized[i++] = tx->tx_in[j].tx_id[BITCOIN_TXID_LENGTH-1-k];
		}
		// index
		write32(tx_serialized+i, tx->tx_in[j].index); i+= 4;
		if(j==index)
		{
			// sign input
			tx_serialized[i++] = tx->tx_in[j].script_length;
			for(k=0; k < tx->tx_in[j].script_length; k++)
			{
				tx_serialized[i++] = tx->tx_in[j].script[k];
			}
		} else {		
			// empty input
			tx_serialized[i++] = 0;
		}
		// sequence
		write32(tx_serialized+i, tx->tx_in[j].sequence);  i += 4;
	}
	
	// out count
	tx_serialized[i++] = tx->tx_out_count;
	// txout
	for(j=0; j < tx->tx_out_count; j++)
	{
		// amount
		write64(tx_serialized+i, tx->tx_out[j].amount); i+= 8;
		// script pub key
		tx_serialized[i++] = tx->tx_out[j].script_length;
		for(k=0; k < tx->tx_out[j].script_length; k++)
		{
			tx_serialized[i++] = tx->tx_out[j].script[k];
		}
	}
	// lock time
	write32(tx_serialized+i, tx->lock_time); i+= 4;
	 
	// hash type
	write32(tx_serialized+i, BITCOIN_SIGHASH_ALL); i+= 4;
	
	// sha256 twice
	unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
	
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, tx_serialized, i);
    SHA256_Final(hash, &sha256);
	
	SHA256_Init(&sha256);
    SHA256_Update(&sha256, hash, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash, &sha256);
	
	// ECDSA sign	
	ecdsa_sign(r, s, hash);	
	
	// DER encode signature
	uint8_t script_sig[200];
	i = 0;
	uint8_t bytes_to_push = i++;
	// DER SEQUENCE
	script_sig[i++] = 0x30;
	// DER Length
	uint8_t der_length = i++;
	script_sig[der_length] = 68;
	// DER Integer r
	script_sig[i++] = 2;
	if(r[0] & 0x80) { 		
		script_sig[i++] = 33; // r length
		script_sig[i++] = 0; // 00 pad
		script_sig[der_length]++;
	} else {
		script_sig[i++] = 32;
	}
	for(j=0; j<32; j++)
	{
		script_sig[i++] = r[j];
	}
	
	// DER Integer s
	script_sig[i++] = 2;
	if(s[0] & 0x80) { 		
		script_sig[i++] = 33; // s length
		script_sig[i++] = 0; // 0 pad
		script_sig[der_length]++;
	} else {
		script_sig[i++] = 32; // s length
	}
	for(j=0; j<32; j++)
	{
		script_sig[i++] = s[j];
	}
	// Hash type
	script_sig[i++] = BITCOIN_SIGHASH_ALL;
	
	script_sig[bytes_to_push] = i-bytes_to_push-1;
	
	// public key
	script_sig[i++] = 33;
	script_sig[i++] = 3;
	for(j=0; j<32; j++)
	{
		script_sig[i++] = public_key[j];
	}
	
	// write script sig
	tx->tx_in[index].script_length = i;
	for(j=0; j<i; j++)
	{
		tx->tx_in[index].script[j] = script_sig[j];
	}
	
}

uint16_t bitcoin_serialize(uint8_t *tx_serialized, bitcoin_tx *tx)
{
	uint16_t i = 0;
	uint8_t j = 0;
	uint8_t k = 0;
	
	// version
	write32(tx_serialized+i, tx->version); i+= 4;
	// in count
	tx_serialized[i++] = tx->tx_in_count;
	// txin
	for(j=0; j < tx->tx_in_count; j++)
	{
		// txid
		for(k=0; k < BITCOIN_TXID_LENGTH; k++)
		{
			tx_serialized[i++] = tx->tx_in[j].tx_id[BITCOIN_TXID_LENGTH-1-k];
		}
		// index
		write32(tx_serialized+i, tx->tx_in[j].index); i+= 4;		
		// script length
		tx_serialized[i++] = tx->tx_in[j].script_length;
		for(k=0; k < tx->tx_in[j].script_length; k++)
		{
			tx_serialized[i++] = tx->tx_in[j].script[k];
		}
		
		// sequence
		write32(tx_serialized+i, tx->tx_in[j].sequence); i += 4;
	}
	
	// out count
	tx_serialized[i++] = tx->tx_out_count;
	// txout
	for(j=0; j < tx->tx_out_count; j++)
	{
		// amount
		write64(tx_serialized+i, tx->tx_out[j].amount); i+= 8;
		// script pub key
		tx_serialized[i++] = tx->tx_out[j].script_length;
		for(k=0; k < tx->tx_out[j].script_length; k++)
		{
			tx_serialized[i++] = tx->tx_out[j].script[k];
		}
	}
	// lock time
	write32(tx_serialized+i, tx->lock_time); i+= 4;	 
	return i;
}

// writes 32bit word to buffer using little endian encoding
void write32(uint8_t *buffer, uint32_t data)
{
	buffer[0] = data & 0xff; data >>= 8;
	buffer[1] = data & 0xff; data >>= 8;
	buffer[2] = data & 0xff; data >>= 8;
	buffer[3] = data & 0xff;
}

// writes 64bit word to buffer using little endian encoding
void write64(uint8_t *buffer, uint64_t data)
{
	buffer[0] = data & 0xff; data >>= 8;
	buffer[1] = data & 0xff; data >>= 8;
	buffer[2] = data & 0xff; data >>= 8;
	buffer[3] = data & 0xff; data >>= 8;
	buffer[4] = data & 0xff; data >>= 8;
	buffer[5] = data & 0xff; data >>= 8;
	buffer[6] = data & 0xff; data >>= 8;
	buffer[7] = data & 0xff;
}