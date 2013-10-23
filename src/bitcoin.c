#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <libusb.h>

#include "m24lr.h"
#include "cr95hf.h"
#include "base58.h"
#include "protocol.h"

#define BITCOIN_TRANSACTION_READY 0x01
#define BITCOIN_UNSPENT_READY 0x02
#define BITCOIN_PENDING 0x20
#define BITCOIN_COMPLETE 0x30

#define MAX_RETRIES 20
#define RETRY_DELAY 10000

#include "bitcoin.h"
#include "bignum32.h"
#include "ecdsa.h"
#include "jsmn.h"

#define TXID_SIZE 32
#define ADDRESS_SIZE 20
#define BTC_TO_SATOSHI 100000000
uint8_t to_address[200] = {0xb4, 0x2c, 0xfe, 0xe4, 0x7e, 0x6c, 0xaf, 0xb6, 0x7c, 0xff, 0x40, 0x6a, 0xb7, 0x8c, 0x7d, 0xa4, 0xd0, 0x55, 0x9f, 0x35};
uint8_t change_address[200] = {0x49, 0x4f, 0xcf, 0x55, 0xac, 0x4e, 0xfb, 0x77, 0xd2, 0x09, 0x85, 0x32, 0x51, 0x2f, 0x42, 0x8e, 0x25, 0x9f, 0x63, 0x42};
uint64_t amount =   100000000; // 1 btc = 10e8 satoshis
uint64_t balance  = 400000000; // current wallet balance

typedef struct {
	uint8_t txid[TXID_SIZE];
	uint8_t script[200];
	uint8_t script_length;
	uint8_t vout;
} tx_input_t;

typedef struct {
	uint64_t value;
	uint8_t address[ADDRESS_SIZE];
} tx_output_t;

tx_output_t tx_outputs[10];
tx_input_t tx_inputs[10];

uint8_t inputs_size = 0;
uint8_t outputs_size = 0;

uint8_t in1_tx_id[200] = {0x53, 0xd9, 0xd9, 0xdc, 0x25, 0xbd, 0x04, 0x92, 0x8c, 0xfe, 0xd1, 0x07, 0x0d, 0x51, 0x0e, 0xcc, 0xb3, 0x46, 0xe3, 0xa8, 0xb3, 0xaa, 0x8d, 0xaf, 0x21, 0x7a, 0xe4, 0xd1, 0x29, 0x36, 0x31, 0xcc};
uint8_t in1_script[225] = {0x76, 0xa9, 0x14, 0x49, 0x4f, 0xcf, 0x55, 0xac, 0x4e, 0xfb, 0x77, 0xd2, 0x09, 0x85, 0x32, 0x51, 0x2f, 0x42, 0x8e, 0x25, 0x9f, 0x63, 0x42, 0x88, 0xac};

uint8_t in2_tx_id[200] = {0xe8, 0x0c, 0x2f, 0x8a, 0x6c, 0x6d, 0x1d, 0xcf, 0x8c, 0x26, 0xa4, 0x72, 0x92, 0x58, 0x5b, 0xd3, 0x55, 0x95, 0x4e, 0xd2, 0xaa, 0x39, 0xcc, 0x20, 0xbd, 0x4f, 0xa1, 0xfe, 0x3f, 0x8c, 0xf2, 0x6b};
uint8_t in2_script[225] = {0x76, 0xa9, 0x14, 0x49, 0x4f, 0xcf, 0x55, 0xac, 0x4e, 0xfb, 0x77, 0xd2, 0x09, 0x85, 0x32, 0x51, 0x2f, 0x42, 0x8e, 0x25, 0x9f, 0x63, 0x42, 0x88, 0xac};

uint8_t public_key[32] = {0x39, 0xA1, 0xE5, 0x74, 0xB4, 0x75, 0xBE, 0x52, 0x04, 0xF7, 0x8C, 0xB3, 0x72, 0x85, 0x4B, 0x4C, 0x85, 0x82, 0x20, 0xBD, 0xE4, 0x92, 0x09, 0x6C, 0x3A, 0xF1, 0xC5, 0xF1, 0xB6, 0x94, 0x4B, 0xC1};

#define MAX_TOKENS 256
#define BUFFER_SIZE 1000

void write32(uint8_t *buffer, uint32_t data);
void write64(uint8_t *buffer, uint64_t data);

int parse_vin(jsmntok_t tokens[], char json_tx[], int i);
int parse_input(jsmntok_t tokens[], char json_tx[], int i, int input_index);
int parse_vout(jsmntok_t tokens[], char json_tx[], int i);
int parse_output(jsmntok_t tokens[], char json_tx[], int i, int output_index);

void sign_hash(uint8_t *hash, uint8_t *r, uint8_t *s);
int write_tx(uint8_t *hash);
int read_tx(uint8_t *r, uint8_t *s);
int set_status(uint8_t status);

uint8_t parse_hex(char hex);
void hex_to_bin(char *hex_string, uint8_t *buffer, int size);
void print_hex(uint8_t *buffer, int size);

int main(int argc, char *argv[])
{
	libusb_device **devs = NULL;
	libusb_device *dev = NULL, *cr95hf = NULL;
	uint8_t hash[DIGEST_LENGTH];
	
	int r,i=0;
	ssize_t cnt;
	
	
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
		
		if(bitcoin_transaction("../server/0001.tx", "../server/0001.signed")==0)
		{
			printf("TX_READY\n");
		} else {
			printf("TX_ERROR\n");
		}
	}
	
	libusb_free_device_list(devs, 1);
}

uint8_t bitcoin_transaction(char *filename, char *output_filename)
{
	uint16_t i,j;
	uint16_t length;
	uint8_t *out;
	uint8_t buffer[BUFFER_SIZE];
	bitcoin_tx transaction;
	int r;
	
	FILE *fp;
	char json_tx[BUFFER_SIZE];
	
	// read JSON tx
	jsmn_parser parser;
	jsmn_init(&parser);
	jsmntok_t tokens[MAX_TOKENS];
	
	fp = fopen(filename, "r");
	if(fp==NULL)
	{
		fprintf(stderr, "Couldn't open 0001.tx\n");
		exit(1);
	}
	fread(json_tx, 1000, 1, fp);
	r = jsmn_parse(&parser, json_tx, tokens, MAX_TOKENS);
	if(r != JSMN_SUCCESS)
	{
		fprintf(stderr, "JSON parsing error %d\n", r);
		exit(1);
	}
	
	for(i=0; i<256; i++)
	{
		jsmntok_t t = tokens[i];
		jsmntok_t nt = tokens[i+1];
		if(t.start == 0 && t.end == 0) break;
		
		if(t.type==JSMN_STRING)
		{
			if(!strncmp("locktime", &json_tx[t.start], t.end-t.start))
				printf("locktime %.*s\n", nt.end-nt.start,&json_tx[nt.start]);
			else if(!strncmp("version", &json_tx[t.start], t.end-t.start))	
				printf("version %.*s\n", nt.end-nt.start,&json_tx[nt.start]);
			else if(!strncmp("vin", &json_tx[t.start], t.end-t.start))	
				i = parse_vin(tokens, json_tx, i+1);
			else if(!strncmp("vout", &json_tx[t.start], t.end-t.start))	
				i = parse_vout(tokens, json_tx, i+1);
		//printf("type %d start %d end %d children %d\n %.*s\n", tokens[i].type, tokens[i].start, tokens[i].end, tokens[i].size, tokens[i].end-tokens[i].start,&json_tx[tokens[i].start]);
		}
	}
	
	for(i=0; i<inputs_size; i++)
	{
		printf("Input %d vout %d\n", i, tx_inputs[i].vout);
		printf("txid \n"); print_hex(tx_inputs[i].txid, TXID_SIZE); printf("\n");
		printf("script \n"); print_hex(tx_inputs[i].script, tx_inputs[i].script_length); printf("\n");
	}
	
	for(i=0; i<inputs_size; i++)
	{
		printf("Output %d value %llu\n", i, tx_outputs[i].value);
		printf("address \n"); print_hex(tx_outputs[i].address, ADDRESS_SIZE); printf("\n");		
	}
		
	struct tx_in transaction_inputs[2];
	struct tx_out transaction_outputs[2];
	
	// build tx
	transaction.version = BITCOIN_TX_VERSION;
	transaction.lock_time = BITCOIN_LOCK_TIME;

	// build txin
	transaction.tx_in_count = inputs_size;
	transaction.tx_in= transaction_inputs;
	
	for(i=0; i<inputs_size; i++)
	{
		transaction.tx_in[i].tx_id = tx_inputs[i].txid;
		transaction.tx_in[i].index = tx_inputs[i].vout;
		transaction.tx_in[i].script = tx_inputs[i].script;
		transaction.tx_in[i].script_length = tx_inputs[i].script_length;
		transaction.tx_in[i].sequence = BITCOIN_SEQUENCE;
	}
	
	// build txout
	transaction.tx_out_count = outputs_size;
	transaction.tx_out = transaction_outputs;
	
	// recipient
	for(i=0; i<outputs_size; i++)
	{
		transaction.tx_out[i].amount = tx_outputs[i].value;
		transaction.tx_out[i].script_length = 25;
		transaction.tx_out[i].script = malloc(25);
		out = transaction.tx_out[i].script;
		out[0] = 0x76; // OP_DUP
		out[1] = 0xA9; // OP_HASH_160
		out[2] = 0x14; // Push 20 bytes
		for(j=0; j<20; j++)
		{
			out[3+j]=tx_outputs[i].address[j];
		}
		out[23] = 0x88; // OP_EQUALVERIFY
		out[24] = 0xac; // OP_CHECKSIG
	}
	
	
	// foreach txin prepare tx for signing
	for(i = 0; i<transaction.tx_in_count; i++)
	{
		bitcoin_sign_input(&transaction, i);
	}
	
	// print hex tx
	length = bitcoin_serialize(buffer, &transaction);	
	fp = fopen(output_filename, "w");
	for(i=0; i<length; i++)
	{
		fprintf(fp, "%02x", buffer[i]);
	}
	fprintf(fp, "\n");
	fclose(fp);
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
	sign_hash(hash, r, s);
	
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

int parse_vin(jsmntok_t tokens[], char json_tx[], int i)
{
	printf("vin type %d %d\n", tokens[i].type, tokens[i].size);
	inputs_size = tokens[i].size;
	int input_index = -1;
	for(; i<MAX_TOKENS; i++)
	{
		jsmntok_t t = tokens[i];
		jsmntok_t nt = tokens[i+1];
		if(t.start == 0 && t.end == 0) break;
		
		if(t.type==JSMN_OBJECT)
		{
			input_index++;
			i = parse_input(tokens, json_tx, i+1, input_index);
			printf("vin %d\n", input_index);
			if(input_index == inputs_size-1)
				return i;
		}
	}
	return i;
}

int parse_input(jsmntok_t tokens[], char json_tx[], int i, int input_index)
{
	int max_tokens = i+6;
	for(; i<max_tokens-1; i++)
	{
		jsmntok_t t = tokens[i];
		jsmntok_t nt = tokens[i+1];
		if(t.start == 0 && t.end == 0) break;		
		
		if(t.type==JSMN_STRING)
		{
			if(!strncmp("txid", &json_tx[t.start], t.end-t.start))
				hex_to_bin(&json_tx[nt.start], tx_inputs[input_index].txid, TXID_SIZE);
			else if(!strncmp("scriptPubKey", &json_tx[t.start], t.end-t.start))
			{
				hex_to_bin(&json_tx[nt.start], tx_inputs[input_index].script, (nt.end-nt.start)/2);
				tx_inputs[input_index].script_length = (nt.end-nt.start)/2;
			}
			else if(!strncmp("vout", &json_tx[t.start], t.end-t.start))
				sscanf(&json_tx[nt.start], "%d", &tx_inputs[input_index].vout);
		} 
	}
	return i;
}

int parse_vout(jsmntok_t tokens[], char json_tx[], int i)
{
	printf("vout type %d %d\n", tokens[i].type, tokens[i].size);
	outputs_size = tokens[i].size;
	int output_index = -1;
	for(; i<MAX_TOKENS; i++)
	{
		jsmntok_t t = tokens[i];
		jsmntok_t nt = tokens[i+1];
		if(t.start == 0 && t.end == 0) break;
		
		if(t.type==JSMN_OBJECT)
		{
			output_index++;
			i = parse_output(tokens, json_tx, i+1, output_index);
			printf("vout %d\n", output_index);
			if(output_index == outputs_size-1)
				return i;
		}
	}
	return i;
}

int parse_output(jsmntok_t tokens[], char json_tx[], int i, int output_index)
{
	int max_tokens = i+4;
	for(; i<max_tokens-1; i++)
	{
		jsmntok_t t = tokens[i];
		jsmntok_t nt = tokens[i+1];
		if(t.start == 0 && t.end == 0) break;		
		
		if(t.type==JSMN_STRING)
		{
			if(!strncmp("value", &json_tx[t.start], t.end-t.start))
			{
				double value;
				sscanf(&json_tx[nt.start], "%lf", &value);
				tx_outputs[output_index].value = (uint64_t) (value * BTC_TO_SATOSHI);				
			}
			else if(!strncmp("address", &json_tx[t.start], t.end-t.start))
				hex_to_bin(&json_tx[nt.start], tx_outputs[output_index].address, ADDRESS_SIZE);			
		} 
	}
	return i;
}

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

void hex_to_bin(char *hex_string, uint8_t *buffer, int size)
{
	int i;
	for(i=0; i<size; i++)
	{
		buffer[i] = (parse_hex(hex_string[2*i])<<4) | parse_hex(hex_string[2*i +1]);
	}
}

void print_hex(uint8_t *buffer, int size)
{
	int i;
	for(i = 0; i<size; i++)
	{
		printf("%02x", buffer[i]);
	}
}

void sign_hash(uint8_t *hash, uint8_t *ecdsa_r, uint8_t *ecdsa_s)
{
	int errors, r,i=0;
	int tx_written = 0;
	int status;
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
			if(errors>MAX_RETRIES) return sign_hash(hash, ecdsa_r, ecdsa_s);
			errors++;
			
			switch(r)
			{
				case 0x86:
					printf("Communications error\n"); break;
				case 0x87:
					printf("Frame timeout error\n"); break;
				case 0x88:
					printf("Invalid SOF error\n"); break;
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
					} else {
						tx_written = 1;
						for(i = 0; i<40; i++)
						{
							usleep(400000);
							r = m24lr_read_block(0, &block);
							status = block>>24;
							if(!r && (status == STATUS_TX_COMPLETE)) break;

							printf("Transaction in progress\n");
							if(!r && status==STATUS_READY)
							{
								printf("TX failed\n");
								break;
							}
							else if(!r)
							{
								printf("other... %d\n", block>>24);
								break;
							}
						}
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
					if(tx_written)
					{
						printf("Transaction complete\n"); 
						r = read_tx(ecdsa_r,ecdsa_s);
						if(r) printf("read_tx error %02x\n", r);
						else return;
					} else {
						printf("Old transaction present\n");
						set_status(STATUS_READY);
					}
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

int read_tx(uint8_t *ecdsa_r, uint8_t *ecdsa_s)
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
		
		ecdsa_r[i*4 + 0] = (block >> 24) & 0xff;
		ecdsa_r[i*4 + 1] = (block >> 16) & 0xff;
		ecdsa_r[i*4 + 2] = (block >>  8) & 0xff;
		ecdsa_r[i*4 + 3] = (block >>  0) & 0xff;
		
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
		
		ecdsa_s[i*4 + 0] = (block >> 24) & 0xff;
		ecdsa_s[i*4 + 1] = (block >> 16) & 0xff;
		ecdsa_s[i*4 + 2] = (block >>  8) & 0xff;
		ecdsa_s[i*4 + 3] = (block >>  0) & 0xff;
		
		printf("%02x%02x%02x%02x", ecdsa_s[i*4 + 0], ecdsa_s[i*4 + 1], ecdsa_s[i*4 + 2], ecdsa_s[i*4 + 3]);
	}
	printf("\n");
	set_status(STATUS_READY);
	return 0;
}