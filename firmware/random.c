/*
 * random.c
 *
 * Created: 3/09/2013 8:45:15 PM
 *  Author: Sam
 */ 
#include <asf.h>
#include "gpio.h"
#include "conf_board.h"

void random_bytes(uint8_t *buffer, uint8_t size)
{	
	uint16_t random_data;
	int i;
	gpio_enable_gpio_pin(RANDA_PIN);
	gpio_enable_gpio_pin(RANDB_PIN);
	
	gpio_clr_gpio_open_drain_pin(RANDA_PIN);
	for(i = 0; i<size/2; i++)
	{
		random_data=0;
		gpio_set_gpio_open_drain_pin(RANDA_PIN);
		while(gpio_pin_is_low(RANDA_PIN))
		{
			random_data++;
		}
		buffer[i*2] = random_data&0xff;
		buffer[i*2+1] = random_data>>8;
		
		gpio_clr_gpio_open_drain_pin(RANDA_PIN);
		while(gpio_pin_is_high(RANDA_PIN))
		{
			;
		}		
	}	
	gpio_clr_gpio_open_drain_pin(RANDA_PIN);
}