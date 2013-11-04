/**
 * \file
 *
 * \brief User board configuration template
 *
 */

#define TWIMS0_TWD_PIN              AVR32_TWIMS0_TWD_0_2_PIN
#define TWIMS0_TWD_FUNCTION         AVR32_TWIMS0_TWD_0_2_FUNCTION
#define TWIMS0_TWCK_PIN             AVR32_TWIMS0_TWCK_0_0_PIN
#define TWIMS0_TWCK_FUNCTION        AVR32_TWIMS0_TWCK_0_0_FUNCTION

#ifndef CONF_BOARD_H
#define CONF_BOARD_H

#define LOCK_LED				AVR32_PIN_PA19
#define LED1					LOCK_LED

#define M24LR_ADDR					0x53
#define M24LR_SYS_ADDR				0x57

#define M24LR_TWI				&AVR32_TWIM0
#define M24LR_TWCK_PIN			AVR32_PIN_PA04
#define M24LR_TWD_PIN			AVR32_PIN_PA05
#define M24LR_BUSY_PIN			AVR32_PIN_PB09
#define M24LR_BUSY_IRQ			AVR32_GPIO_IRQ_3
#define M24LR_BUSY_LEVEL		1

#define RANDB_PIN			AVR32_PIN_PB06
#define RANDA_PIN			AVR32_PIN_PB07

#define TOUCH1_B_PIN		AVR32_PIN_PB06
#define TOUCH1_A_PIN		AVR32_PIN_PB07

#define BOARD_OSC0_IS_XTAL true
#define BOARD_OSC0_HZ 10000000
#define BOARD_OSC0_STARTUP_US 10000
#define OSC0_GAIN_VALUE 0


#endif // CONF_BOARD_H
