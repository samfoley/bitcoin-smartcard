/*
 * i2c.c
 *
 * Created: 19/09/2013 12:36:56 PM
 *  Author: Sam
 */ 

#include <asf.h>
#include "i2c.h"
#include "conf_board.h"

#define I2C_READ 1
#define I2C_WRITE 0

#define SCL_PIN M24LR_TWCK_PIN
#define SDA_PIN M24LR_TWD_PIN

// from http://en.wikipedia.org/wiki/I%C2%B2C#Example_of_bit-banging_the_I.C2.B2C_Master_protocol

// Hardware-specific support functions that MUST be customized:
#define I2CSPEED 1000

//void I2C_delay() { volatile int v; int i; for (i=0; i < I2CSPEED/2; i++) v; }
void I2C_delay() { delay_us(10); }
bool read_SCL(void) // Set SCL as input and return current level of line, 0 or 1
{
	gpio_configure_pin(SCL_PIN, GPIO_DIR_INPUT);
	return gpio_get_pin_value(SCL_PIN);
}

bool read_SDA(void) // Set SDA as input and return current level of line, 0 or 1
{
	gpio_configure_pin(SDA_PIN, GPIO_DIR_INPUT);
	return gpio_get_pin_value(SDA_PIN);
}

void clear_SCL(void) // Actively drive SCL signal low
{
	gpio_configure_pin(SCL_PIN, GPIO_DIR_OUTPUT | GPIO_OPEN_DRAIN);
	gpio_set_pin_low(SCL_PIN);
}

void clear_SDA(void) // Actively drive SDA signal low
{
	gpio_configure_pin(SDA_PIN, GPIO_DIR_OUTPUT | GPIO_OPEN_DRAIN);
	gpio_set_pin_low(SDA_PIN);
}

void arbitration_lost(void)
{
	int i;
	while(1)
	{
		i++;
	}
	
}

bool started = false; // global data
void i2c_start_cond(void) {
	if (started) { // if started, do a restart cond
		// set SDA to 1
		read_SDA();
		I2C_delay();
		while (read_SCL() == 0) {  // Clock stretching
			// You should add timeout to this loop
		}
		// Repeated start setup time, minimum 4.7us
		I2C_delay();
	}
	if (read_SDA() == 0) {
		arbitration_lost();
	}
	// SCL is high, set SDA from 1 to 0.
	clear_SDA();
	I2C_delay();
	clear_SCL();
	started = true;
}

void i2c_stop_cond(void){
	// set SDA to 0
	clear_SDA();
	I2C_delay();
	// Clock stretching
	while (read_SCL() == 0) {
		// add timeout to this loop.
	}
	// Stop bit setup time, minimum 4us
	I2C_delay();
	// SCL is high, set SDA from 0 to 1
	if (read_SDA() == 0) {
		arbitration_lost();
	}
	I2C_delay();
	started = false;
}

// Write a bit to I2C bus
void i2c_write_bit(bool bit) {
	if (bit) {
		read_SDA();
		} else {
		clear_SDA();
	}
	I2C_delay();
	while (read_SCL() == 0) { // Clock stretching
		// You should add timeout to this loop
	}
	// SCL is high, now data is valid
	// If SDA is high, check that nobody else is driving SDA
	if (bit && read_SDA() == 0) {
		arbitration_lost();
	}
	I2C_delay();
	clear_SCL();
}

// Read a bit from I2C bus
bool i2c_read_bit(void) {
	bool bit;
	// Let the slave drive data
	read_SDA();
	I2C_delay();
	while (read_SCL() == 0) { // Clock stretching
		// You should add timeout to this loop
	}
	// SCL is high, now data is valid
	bit = read_SDA();
	I2C_delay();
	clear_SCL();
	return bit;
}

// Write a byte to I2C bus. Return 0 if ack by the slave.
bool i2c_write_byte(bool send_start,
bool send_stop,
unsigned char byte) {
	unsigned bit;
	bool nack;
	if (send_start) {
		i2c_start_cond();
	}
	for (bit = 0; bit < 8; bit++) {
		i2c_write_bit((byte & 0x80) != 0);
		byte <<= 1;
	}
	nack = i2c_read_bit();
	if (send_stop) {
		i2c_stop_cond();
	}
	return nack;
}

// Read a byte from I2C bus
unsigned char i2c_read_byte(bool nack, bool send_stop) {
	unsigned char byte = 0;
	unsigned bit;
	for (bit = 0; bit < 8; bit++) {
		byte = (byte << 1) | i2c_read_bit();
	}
	i2c_write_bit(nack);
	if (send_stop) {
		i2c_stop_cond();
	}
	return byte;
}

status_code_t i2c_write (volatile avr32_twim_t *twim, const uint8_t *buffer, uint32_t nbytes, uint32_t saddr,
	bool tenbit)
{
	uint8_t device_select = saddr<<1 | I2C_WRITE;
	uint8_t i;
	
	if(i2c_write_byte(true, false, device_select)) return ERR_IO_ERROR;
	
	for(i = 0; i<nbytes; i++)
	{
		if(i2c_write_byte(false, (i+1 == nbytes), buffer[i])) return ERR_IO_ERROR;
	}
	return STATUS_OK;
}

status_code_t i2c_read (volatile avr32_twim_t *twim, uint8_t *buffer,
	uint32_t nbytes, uint32_t saddr, bool tenbit)
{
	uint8_t device_select = saddr<<1 | I2C_READ;
	uint8_t i;
	
	if(i2c_write_byte(true, false, device_select)) return ERR_IO_ERROR;
	
	for(i = 0; i<nbytes; i++)
	{
		buffer[i] = i2c_read_byte((i+1==nbytes), (i+1==nbytes));
	}
	return STATUS_OK;
}