/*
    \file   cli.c

    \brief  Command Line Interpreter source file.

    (c) 2018 Microchip Technology Inc. and its subsidiaries.

    Subject to your compliance with these terms, you may use Microchip software and any
    derivatives exclusively with Microchip products. It is your responsibility to comply with third party
    license terms applicable to your use of third party software (including open source software) that
    may accompany Microchip software.

    THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
    EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY
    IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS
    FOR A PARTICULAR PURPOSE.

    IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
    INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
    WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP
    HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO
    THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL
    CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT
    OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS
    SOFTWARE.
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <avr/wdt.h>

#include "usart_basic.h"
#include "cli.h"
#include "../cloud/crypto_client/crypto_client.h"
#include "../credentials_storage/credentials_storage.h"
#include "../mqtt/mqtt_core/mqtt_core.h"
#include "debug_print.h"
#include "../cloud/wifi_service.h"
#include "../mqtt/mqtt_comm_bsd/mqtt_comm_layer.h"
#include "../cloud/cloud_service.h"

#define WIFI_PARAMS_OPEN 1
#define WIFI_PARAMS_PSK 2
#define WIFI_PARAMS_WEP 3
#define DEVICE_INFORMATION_PARAMS 2
#define DEVICE_SECRET_PARAMS 1
#define DEVICE_PARAMS 3
#define MAX_COMMAND_SIZE 100
#define MAX_PUB_KEY_LEN 200
#define NEWLINE "\r\n"

#define UNKNOWN_CMD_MSG                                                                                                \
	"--------------------------------------------" NEWLINE "Unknown command. List of available commands:" NEWLINE      \
	"reset" NEWLINE "device" NEWLINE "device_information" NEWLINE "device_secret" NEWLINE "reconnect" NEWLINE          \
	"version" NEWLINE "cli_version" NEWLINE "wifi <ssid>[,<pass>,[authType]]" NEWLINE "debug" NEWLINE                  \
	"--------------------------------------------" NEWLINE "\4"

static char    command[MAX_COMMAND_SIZE];
static bool    isCommandReceived  = false;
static uint8_t index              = 0;
static bool    commandTooLongFlag = false;

const char *const cli_version_number      = "2.1";
const char *const firmware_version_number = "1.1.1";

static void command_received(char *command_text);
static void reset_cmd(char *pArg);
static void reconnect_cmd(char *pArg);
static void set_wifi_auth(char *ssid_pwd_auth);
static void set_device_information(char *device_information);
static void set_device_secret(char *device_secret);
static void get_device_id(char *pArg);
static void get_cli_version(char *pArg);
static void get_firmware_version(char *pArg);
static void set_debug_level(char *pArg);

static bool endOfLineTest(char c);
static void enableUsartRxInterrupts(void);

#define CLI_TASK_INTERVAL 50

absolutetime_t CLI_task(void *);
timer_struct_t CLI_task_timer = {CLI_task};

struct cmd {
	const char *const command;
	void (*const handler)(char *argument);
};

const struct cmd commands[] = {{"reset", reset_cmd},
                               {"reconnect", reconnect_cmd},
                               {"wifi", set_wifi_auth},
                               {"device_information", set_device_information},
                               {"device_secret", set_device_secret},
                               {"device", get_device_id},
                               {"cli_version", get_cli_version},
                               {"version", get_firmware_version},
                               {"debug", set_debug_level}};

void CLI_init(void)
{
	enableUsartRxInterrupts();
	scheduler_timeout_create(&CLI_task_timer, CLI_TASK_INTERVAL);
}

static bool endOfLineTest(char c)
{
	static char test     = 0;
	bool        retvalue = true;

	if (c == '\n') {
		if (test == '\r') {
			retvalue = false;
		}
	}
	test = c;
	return retvalue;
}

absolutetime_t CLI_task(void *param)
{
	bool cmd_rcvd = false;
	char c        = 0;
	// read all the EUSART bytes in the queue
	while (USART_0_is_rx_ready() && !isCommandReceived) {
		c = USART_0_read();
		// read until we get a newline
		if (c == '\r' || c == '\n') {
			command[index] = 0;

			if (!commandTooLongFlag) {
				if (endOfLineTest(c) && !cmd_rcvd) {
					command_received((char *)command);
					cmd_rcvd = true;
				}
			}
			if (commandTooLongFlag) {
				printf(NEWLINE "Command too long" NEWLINE);
			}
			index              = 0;
			commandTooLongFlag = false;
		} else // otherwise store the character
		{
			if (index < MAX_COMMAND_SIZE) {
				command[index++] = c;
			} else {
				commandTooLongFlag = true;
			}
		}
	}

	return CLI_TASK_INTERVAL;
}

static void set_wifi_auth(char *ssid_pwd_auth)
{
	char *  credentials[3];
	char *  pch;
	uint8_t params = 0;
	uint8_t i;

	for (i = 0; i <= 2; i++)
		credentials[i] = '\0';

	pch            = strtok(ssid_pwd_auth, ",");
	credentials[0] = pch;

	while (pch != NULL && params <= 2) {
		credentials[params] = pch;
		params++;
		pch = strtok(NULL, ",");
	}

	if (credentials[0] != NULL) {
		if (credentials[1] == NULL && credentials[2] == NULL)
			params = 1;
		else if (credentials[1] != NULL && credentials[2] == NULL) {
			params = atoi(credentials[1]); // Resuse the same variable to store the auth type
			if (params == 2 || params == 3)
				params = 5;
			else if (params == 1)
				;
			else
				params = 2;
		} else
			params = atoi(credentials[2]);
	}

	switch (params) {
	case WIFI_PARAMS_OPEN:
		strncpy(ssid, credentials[0], MAX_WIFI_CREDENTIALS_LENGTH - 1);
		strcpy(pass, "\0");
		strcpy(authType, "1");
		break;

	case WIFI_PARAMS_PSK:
	case WIFI_PARAMS_WEP:
		strncpy(ssid, credentials[0], MAX_WIFI_CREDENTIALS_LENGTH - 1);
		strncpy(pass, credentials[1], MAX_WIFI_CREDENTIALS_LENGTH - 1);
		sprintf(authType, "%d", params);
		break;

	default:
		params = 0;
		break;
	}
	if (params) {
		printf("OK\r\n\4");
		if (CLOUD_isConnected()) {
			MQTT_Close(MQTT_GetClientConnectionInfo());
		}
		wifi_disconnectFromAp();
	} else {
		printf("Error. Wi-Fi command format is wifi <ssid>[,<pass>,[authType]]\r\n\4");
	}
}

static void set_device_information(char *pdevice_information)
{
	char *  deviceInformation[2];
	char *  pch;
	uint8_t params = 0;

	pch = strtok(pdevice_information, ",");
	while (pch != NULL && params <= DEVICE_INFORMATION_PARAMS) {
		deviceInformation[params++] = pch;
		pch                         = strtok(NULL, ", ");
	}

	switch (params) {
	case DEVICE_INFORMATION_PARAMS:
		strncpy(productKey, deviceInformation[0], MAX_PRODUCT_KEY_LENGTH);
		strncpy(deviceName, deviceInformation[1], MAX_DEVICE_NAME_LENGTH);
		productKey[MAX_PRODUCT_KEY_LENGTH] = '\0';
		deviceName[MAX_DEVICE_NAME_LENGTH] = '\0';
		DEVICE_INFORMATION_save(productKey, deviceName);
		break;

	default:
		params = 0;
		break;
	}

	if (params) {
		printf("OK\r\n\4");
		if (CLOUD_isConnected()) {
			MQTT_Close(MQTT_GetClientConnectionInfo());
		}
	} else {
		printf("Error. Device Information format is device <productKey>,<deviceName>.\r\n\4");
	}
}

static void set_device_secret(char *pdevice_secret)
{
	strncpy(deviceSecret, pdevice_secret, DEVICE_SECRET_LENGTH);
	deviceSecret[DEVICE_SECRET_LENGTH] = '\0';
	DEVICE_SECRET_save(deviceSecret);
	printf("OK\r\n\4");
	if (CLOUD_isConnected()) {
		MQTT_Close(MQTT_GetClientConnectionInfo());
	}
}

static void reconnect_cmd(char *pArg)
{
	(void)pArg;

	MQTT_Disconnect(MQTT_GetClientConnectionInfo());
	printf("OK\r\n");
}

static void reset_cmd(char *pArg)
{
	(void)pArg;

	wdt_enable(WDTO_30MS);
	while (1) {
	};
}

static void set_debug_level(char *pArg)
{
	debug_severity_t level = SEVERITY_NONE;
	if (*pArg >= '0' && *pArg <= '4') {
		level = *pArg - '0';
		debug_setSeverity(level);
		printf("OK\r\n");
	} else {
		printf("debug parameter must be between 0 (Least) and 4 (Most) \r\n");
	}
}

static char *ateccsn = NULL;
void         CLI_setdeviceId(char *id)
{
	ateccsn = id;
}

static void get_device_id(char *pArg)
{
	(void)pArg;
	if (ateccsn) {
		printf("%s\r\n\4", ateccsn);
	} else {
		printf("Unknown.\r\n\4");
	}
}

static void get_cli_version(char *pArg)
{
	(void)pArg;
	printf("v%s\r\n\4", cli_version_number);
}

static void get_firmware_version(char *pArg)
{
	(void)pArg;
	printf("v%s\r\n\4", firmware_version_number);
}

static void command_received(char *command_text)
{
	char *  argument = strstr(command_text, " ");
	uint8_t cmp;
	uint8_t ct_len;
	uint8_t cc_len;
	uint8_t i = 0;

	if (argument != NULL) {
		/* Replace the delimiter with string terminator */
		*argument = '\0';
		/* Point after the string terminator, to the actual string */
		argument++;
	}

	for (i = 0; i < sizeof(commands) / sizeof(*commands); i++) {
		cmp    = strcmp(command_text, commands[i].command);
		ct_len = strlen(command_text);
		cc_len = strlen(commands[i].command);

		if (cmp == 0 && ct_len == cc_len) {
			if (commands[i].handler != NULL) {
				commands[i].handler(argument);
				return;
			}
		}
	}

	printf(UNKNOWN_CMD_MSG);
}

static void enableUsartRxInterrupts(void)
{
	// Empty RX buffer
	do {
		(void)USART2.RXDATAL;
	} while ((USART2.STATUS & USART_RXCIF_bm) != 0);

	// Enable RX interrupt
	USART2.CTRLA |= 1 << USART_RXCIE_bp;
}
