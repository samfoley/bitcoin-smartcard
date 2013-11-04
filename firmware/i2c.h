/*
 * i2c.h
 *
 * Created: 19/09/2013 12:37:14 PM
 *  Author: Sam
 */ 


#ifndef I2C_H_
#define I2C_H_


unsigned char i2c_read_byte(bool nack, bool send_stop);
bool i2c_write_byte(bool send_start, bool send_stop, unsigned char byte);

// Using TWIM module definition for compatibility
status_code_t i2c_write (volatile avr32_twim_t *twim, const uint8_t *buffer, uint32_t nbytes, uint32_t saddr,
 bool tenbit);
 
status_code_t i2c_read (volatile avr32_twim_t *twim, uint8_t *buffer,
	uint32_t nbytes, uint32_t saddr, bool tenbit); 
	
#endif /* I2C_H_ */