#ifndef IOT_SENSOR_NODE_CONFIG_H
#define IOT_SENSOR_NODE_CONFIG_H

#include "../winc/driver/include/m2m_wifi.h"
#include "config/conf_winc.h"

// <h> Application Configuration

// <o> Send Interval <0-100000>
// <i> Send interval in seconds
// <id> application_send_interval
#define CFG_SEND_INTERVAL 1

// <o> Timeout <0-100000>
// <i> Timeout
// <id> application_timeout
#define CFG_TIMEOUT 5000

// </h>

// <h> Cloud Configuration

// <s> project id
// <i> Google Cloud Platform project id
// <id> project_id
#define CFG_PRODUCT_KEY "a11v7xKKAWn"

// <s> registry id
// <i> Google Cloud Platform registry id
// <id> registry_id
#define CFG_DEVICE_NAME "AC5C"

#define CFG_DEVICE_SECRET "uzbhqsD8gRFuwX4HmUJiMShMmxclNMVu"

#define CFG_WRITE_DEVICE_SECRET 1

#define MAX_PRODUCT_KEY_LENGTH 11
#define MAX_DEVICE_NAME_LENGTH 30
#define DEVICE_SECRET_LENGTH 32
// <s> mqtt host
// <i> mqtt host address
// <id> mqtt_host
#define CFG_MQTT_HOST_SUFFIX ".iot-as-mqtt.cn-shanghai.aliyuncs.com"


#ifdef ID2_TEST
#define CFG_MQTT_HOST "id2.cn-shanghai.aliyuncs.com"
#else
#define CFG_MQTT_HOST CFG_PRODUCT_KEY CFG_MQTT_HOST_SUFFIX
#endif
// </h>

// <h> Debug Configuration

// <q> Enable debug messages:
// <i> Check to enable debug messages
// <id> debug_msg
#define CFG_DEBUG_MSG 1

// </h>

// <h> CLI Support

// <q> Enable CLI:
// <i> Check to enable cli
// <id> enable_cli
#define CFG_ENABLE_CLI 1

#define MQTT_COMM_PORT_TLS 443

// </h>

#endif // IOT_SENSOR_NODE_CONFIG_H
