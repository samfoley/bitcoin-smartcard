/**
 * \file
 *
 * \brief Empty user application template
 *
 */

/**
 * \mainpage User Application template doxygen documentation
 *
 * \par Empty user application template
 *
 * Bare minimum empty user application template
 *
 * \par Content
 *
 * -# Include the ASF header files (through asf.h)
 * -# Minimal main function that starts with a call to board_init()
 * -# "Insert application code here" comment
 *
 */

/*
 * Include header files for all drivers that have been imported from
 * Atmel Software Framework (ASF).
 */
#include <asf.h>
#include "twim.h"
#include "bignum32.h"
#include "ecdsa.h"
#include "protocol.h"
#include "gpio.h"
#include "led.h"
#include "conf_board.h"
#include "conf_sleepmgr.h"
#include "i2c.h"	

// Private functions
uint8_t get_status(void);
status_code_t set_status(uint8_t status);

ISR(m24lr_ready_interrupt_handler, M24LR_BUSY_IRQ, M24LR_BUSY_LEVEL)
{
	if(gpio_get_pin_interrupt_flag(M24LR_BUSY_PIN))
	{		
		gpio_toggle_pin(LOCK_LED);
		gpio_clear_pin_interrupt_flag(M24LR_BUSY_PIN);
	}
	return;
}

static void init_touch(void)
{
	uint32_t random_data;
	int i;
	gpio_enable_gpio_pin(RANDA_PIN);
	gpio_enable_gpio_pin(RANDB_PIN);
	
	while(1)
	{			
		gpio_clr_gpio_open_drain_pin(RANDB_PIN);
		
		random_data=0;
		gpio_set_gpio_open_drain_pin(RANDB_PIN);
		while(gpio_pin_is_low(RANDB_PIN))
		{
			random_data++;
		}		
		
		gpio_clr_gpio_open_drain_pin(RANDB_PIN);
		while(gpio_pin_is_high(RANDB_PIN))
		{
			;
		}
		
		gpio_clr_gpio_open_drain_pin(RANDB_PIN);	
	}
}

static void init_gpio(void)
{
	gpio_enable_gpio_pin(RANDA_PIN);
	gpio_enable_gpio_pin(RANDB_PIN);
	//gpio_configure_pin(RANDA_PIN, GPIO_DIR_OUTPUT);
	//gpio_configure_pin(RANDB_PIN, GPIO_DIR_OUTPUT);
	gpio_disable_pin_pull_up(RANDA_PIN);
	gpio_disable_pin_pull_up(RANDB_PIN);
	gpio_set_pin_low(RANDA_PIN);	
	gpio_set_pin_low(RANDB_PIN);
	
	gpio_enable_gpio_pin(LOCK_LED);
	gpio_configure_pin(LOCK_LED, GPIO_DIR_OUTPUT);
	
	Disable_global_interrupt();
	INTC_init_interrupts();
	INTC_register_interrupt(&m24lr_ready_interrupt_handler, AVR32_GPIO_IRQ_0 + M24LR_BUSY_PIN/8, M24LR_BUSY_LEVEL);
	gpio_enable_pin_interrupt(M24LR_BUSY_PIN, GPIO_RISING_EDGE);
	Enable_global_interrupt();
	
	// eic interrupt on end of RF BUSY
	eic_options_t eic_options;
	eic_options.eic_async = EIC_ASYNCH_MODE;
	eic_options.eic_level = EIC_LEVEL_HIGH_LEVEL;
	eic_options.eic_edge = EIC_EDGE_RISING_EDGE;
	eic_options.eic_mode = EIC_MODE_LEVEL_TRIGGERED;
	eic_options.eic_line = EXT_INT3;
	
	gpio_enable_module_pin(M24LR_BUSY_PIN,  AVR32_EIC_EXTINT_1_1_FUNCTION);
	eic_init(&AVR32_EIC, &eic_options, 1);
	eic_enable_line(&AVR32_EIC, EXT_INT3);
	eic_enable_interrupt_line(&AVR32_EIC, EXT_INT3);
	//pm_asyn_wake_up_enable()
}



void twi_init(void)
{
	int status;
	
	status = i2c_write_byte(true, false, M24LR_ADDR<<1);
	uint8_t buffer[3] = {0x00, 0x00, 0xBA};
	status = i2c_write(M24LR_TWI, buffer, 3, M24LR_ADDR, false);
	status = get_status();
	
	gpio_map_t TWI_GPIO_MAP =
	{
		{M24LR_TWD_PIN,  TWIMS0_TWD_FUNCTION  },
		{M24LR_TWCK_PIN, TWIMS0_TWCK_FUNCTION }
	};
	
	gpio_configure_pin(M24LR_TWD_PIN, GPIO_OPEN_DRAIN | GPIO_DIR_OUTPUT);
	gpio_configure_pin(M24LR_TWCK_PIN, GPIO_OPEN_DRAIN | GPIO_DIR_OUTPUT);
	gpio_set_pin_low(M24LR_TWCK_PIN);
	gpio_set_pin_low(M24LR_TWD_PIN);
	
	gpio_enable_module(TWI_GPIO_MAP,
		sizeof(TWI_GPIO_MAP) / sizeof (TWI_GPIO_MAP[0]));			
	
	twi_master_options_t opt = {
		.speed = 50000,
		.chip  = 0x57,
		.pba_hz = 5000000,
		.smbus = false
	};				  	
	status = sysclk_get_cpu_hz();
	status = sysclk_get_pba_hz();
	sysclk_enable_pba_module(SYSCLK_TWIM0);		
	status = twi_master_init(M24LR_TWI, &opt);	
}

status_code_t m24lr_write_bytes(uint16_t address, uint8_t *data, uint8_t nbytes)
{
	uint8_t write_buffer[3];
	uint8_t i;
	status_code_t ok;		
	
	while(gpio_pin_is_low(M24LR_BUSY_PIN));
	
	for(i = 0; i<nbytes; i++)
	{
		write_buffer[0] = address>>8;
		write_buffer[1] = address & 0xff;
		write_buffer[2] = data[i];
		
		while((ok = i2c_write(M24LR_TWI, write_buffer, sizeof(write_buffer), M24LR_ADDR, false)) != STATUS_OK);
		address++;
	}
	return ok;
}

status_code_t m24lr_read_bytes(uint16_t address, uint8_t *data, uint8_t nbytes)
{
	uint8_t address_buffer[2] = { address>>8, address&0xff };
	status_code_t ok;
	
	while(gpio_pin_is_low(M24LR_BUSY_PIN));
	
	while((ok = i2c_write(M24LR_TWI, address_buffer, sizeof(address_buffer), M24LR_ADDR, false)) != STATUS_OK);
	
	if(ok != STATUS_OK) return ok;
	
	while((ok = i2c_read(M24LR_TWI, data, nbytes, M24LR_ADDR, false)) != STATUS_OK);
	
	return ok;
}

status_code_t set_status(uint8_t status)
{
	while(gpio_pin_is_low(M24LR_BUSY_PIN));
	
	return m24lr_write_bytes(STATUS_OFFSET, &status, 1);
}

uint8_t get_status(void)
{
	uint8_t status;
	
	while(gpio_pin_is_low(M24LR_BUSY_PIN));
	
	m24lr_read_bytes(STATUS_OFFSET, &status, 1);
	return status;
}

int main (void)
{
	uint8_t r[32] = {0};
	uint8_t s[32] = {0};
	uint8_t digest[32] = {0};
	int i;
	status_code_t ok;
	uint8_t status;
	
	board_init();
	sysclk_init();
	
	status = sysclk_get_cpu_hz();
	scif_configure_osc_crystalmode(SCIF_OSC0, 10000000);
	i = scif_enable_osc(SCIF_OSC0, 10000, true);
	/*
	sysclk_set_source(SYSCLK_SRC_OSC0);
	sysclk_set_prescalers(0,1,1);
	*/
	
	/*
	AVR32_SCIF.oscctrl0 = AVR32_SCIF_OSCCTRL0_MODE_CRYSTAL<<AVR32_SCIF_OSCCTRL0_MODE_OFFSET | AVR32_SCIF_OSCCTRL0_STARTUP_16384_RCOSC<<AVR32_SCIF_OSCCTRL0_STARTUP_OFFSET;
	AVR32_SCIF.oscctrl0 |= AVR32_SCIF_OSCEN;
	while (!(AVR32_SCIF.pclksr & AVR32_SCIF_PCLKSR_OSC0RDY_MASK));
	AVR32_PM.mcctrl |= AVR32_PM_MCCTRL_MCSEL_MASK & 1;
	*/
	//twi_init();

	init_gpio();
	//init_touch();
	
	LED_On(LOCK_LED);
	set_status(STATUS_READY);		
	LED_Off(LOCK_LED);
	
	
	while(status = get_status())
	{
		switch(status)
		{
			case STATUS_TX_WAITING:
				set_status(STATUS_TX_IN_PROGRESS);
				sysclk_set_source(SYSCLK_SRC_OSC0);
				m24lr_read_bytes(DIGEST_OFFSET, digest, DIGEST_LENGTH);
				
				LED_On(LED1);
				
				ecdsa_sign(r,s,digest);
				
				LED_Off(LED1);
				
				m24lr_write_bytes(R_OFFSET, r, R_LENGTH);
				m24lr_write_bytes(S_OFFSET, s, S_LENGTH);
				set_status(STATUS_TX_COMPLETE);
				sysclk_set_source(SYSCLK_SRC_RCSYS);
				break;
		}
		delay_ms(500);
		gpio_toggle_pin(LOCK_LED);
		//pm_sleep(AVR32_PM_SMODE_STANDBY);
	}
}
