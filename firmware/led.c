/*
 * led.c
 *
 * Created: 4/09/2013 8:52:50 PM
 *  Author: Sam
 */ 
#include <asf.h>
#include "conf_board.h"

void LED_On(U32 leds)
{
	gpio_set_pin_high(LOCK_LED);
}

void LED_Off(U32 leds)
{
	gpio_set_pin_low(LOCK_LED);
}