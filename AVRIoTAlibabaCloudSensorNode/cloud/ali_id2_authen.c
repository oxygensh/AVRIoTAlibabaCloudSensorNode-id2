/*
 * ali_id2_authen.c
 *
 * Created: 2019/5/17 10:34:02
 *  Author: A41547
 */ 
#include "ali_id2_authen.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <atomic.h>
#include "cloud_service.h"
#include "cloud/bsd_adapter/bsdWINC.h"
#include "config/IoT_Sensor_Node_config.h"
#include "cloud/crypto_client/crypto_client.h"
#include "cloud/crypto_client/cryptoauthlib_main.h"
#include "debug_print.h"
#include "include/timeout.h"
#include "cloud/mqtt_packetPopulation/mqtt_packetPopulate.h"
#include "mqtt/mqtt_core/mqtt_core.h"
#include "wifi_service.h"

static uint8_t s_id2_client_inited_flag = false;

/* Fixed POP Header, Total 325 */
uint8_t id2_request[1024] = {
	0x50, 0x4f, 0x53, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d,   /* POST / HTTP/1.1. */
	0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67,   /* .Accept-Encoding */
	0x3a, 0x20, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x0d, 0x0a, 0x78, 0x2d, 0x73, 0x64,   /* : identity..x-sd */
	0x6b, 0x2d, 0x69, 0x6e, 0x76, 0x6f, 0x6b, 0x65, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x6e,   /* k-invoke-type: n */
	0x6f, 0x72, 0x6d, 0x61, 0x6c, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x61,   /* ormal..Accept: a */
	0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, 0x6d, 0x6c, 0x0d, 0x0a,   /* pplication/xml.. */
	0x78, 0x2d, 0x73, 0x64, 0x6b, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x4a, 0x61,   /* x-sdk-client: Ja */
	0x76, 0x61, 0x2f, 0x32, 0x2e, 0x30, 0x2e, 0x30, 0x0d, 0x0a, 0x43, 0x61, 0x63, 0x68, 0x65, 0x2d,   /* va/2.0.0..Cache- */
	0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x3a, 0x20, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68,   /* Control: no-cach */
	0x65, 0x0d, 0x0a, 0x50, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x3a, 0x20, 0x6e, 0x6f, 0x2d, 0x63, 0x61,   /* e..Pragma: no-ca */
	0x63, 0x68, 0x65, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a,   /* che..User-Agent: */
	0x20, 0x4a, 0x61, 0x76, 0x61, 0x2f, 0x31, 0x2e, 0x38, 0x2e, 0x30, 0x5f, 0x31, 0x36, 0x32, 0x0d,   /*  Java/1.8.0_162. */
	0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x69, 0x64, 0x32, 0x2e, 0x63, 0x6e, 0x2d, 0x73, 0x68,   /* .Host: id2.cn-sh */
	0x61, 0x6e, 0x67, 0x68, 0x61, 0x69, 0x2e, 0x61, 0x6c, 0x69, 0x79, 0x75, 0x6e, 0x63, 0x73, 0x2e,   /* anghai.aliyuncs. */
	0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a,   /* com..Connection: */
	0x20, 0x6b, 0x65, 0x65, 0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x0d, 0x0a, 0x43, 0x6f, 0x6e,   /*  keep-alive..Con */
	0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69,   /* tent-type: appli */
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, 0x2d, 0x77, 0x77, 0x77, 0x2d, 0x66, 0x6f, 0x72,   /* cation/x-www-for */
	0x6d, 0x2d, 0x75, 0x72, 0x6c, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x64, 0x0d, 0x0a, 0x43, 0x6f,   /* m-urlencoded..Co */
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x33, 0x32,   /* ntent-Length: 32 */
	0x35, 0x0d, 0x0a, 0x0d, 0x0a                                                                     /* 3....            */
};

// TODO
// Test Data:
// ACCESS_KEY = "LTAIXQlg58OsZV6X"
// ACCESS_SECRET(Store in Slot, used for hmac-sha1) = "A7VpZJDQYmzAfa9YpbcagCjL46bNFL"
// String id2 = "00FFFF00FFFFFF073EC5AC00";
// String authCode = "0~0~6C15FE4F5C681040~F864CFED7EB2F58C60D2F960FA24407D~0V6nSG7yh7goaIIZyCHMiz4mvDTh2GH0dPbFKYhbaCY=";
// String extra = "digest1234";
// String apiVersion = "1.1.2";
// String productKey = "r5oWHGVkfIw";
// String id2 Password (Store in slot, used for AEC128) = WgozbTh8rQG/ER9O1AluLQ==

void updateID2(void)
{
	
}
void connectID2(void)
{
	
	//uint32_t currentTime = time(NULL);

	// if (currentTime > 0)
	//{
	// The JWT takes time in UNIX format (seconds since 1970), AVR-LIBC uses seconds from 2000 ...
	//updateJWT(currentTime + UNIX_OFFSET);
	//MQTT_CLIENT_connect();
	//}
	//debug_print("CLOUD: MQTT Connect");

	// MQTT SUBSCRIBE packet will be sent after the MQTT connection is established.
	//sendSubscribe = true;
}

// TODO
irot_result_t id2_client_init(void)
{
	// 
	return IROT_SUCCESS;
}

irot_result_t id2_client_get_version(uint32_t* pversion)
{
    irot_result_t ret = IROT_SUCCESS;
    if (s_id2_client_inited_flag != true)
    {
	    //id2_log_error("ERROR: [%s] id2 client not inited.\n", __FUNC_NAME__);
	    ret = IROT_ERROR_GENERIC;
    }
    else
    {
	    *pversion = ID2_CLIENT_VERSION_NUMBER;
    }
    return ret;
}

// TODO
irot_result_t id2_client_get_id(uint8_t* id, uint32_t* len)
{
	// Return, ID2 String
	return IROT_SUCCESS;
}

// TODO
static irot_result_t id2_hash(uint8_t* sign_in, uint32_t sign_in_len, uint8_t* hash_buf, uint32_t* hash_len)
{
	// Return hash result
	// Example£º
	// Sign_in = POST&%2F&AccessKeyId%3DLTAIXQlg58OsZV6X%26Action%3DVerify%26ApiVersion%3D1.1.2%26AuthCode%3D0~0~6C15FE4F5C681040~F864CFED7EB2F58C60D2F960FA24407D~0V6nSG7yh7goaIIZyCHMiz4mvDTh2GH0dPbFKYhbaCY%253D%26Extra%3Ddigest1234%26Format%3DXML%26Id2%3D00FFFF00FFFFFF073EC5AC00%26ProductKey%3Dr5oWHGVkfIw%26RegionId%3Dcn-shanghai%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3D579f7d09-b47b-443f-b0ab-1f80d2795fa0%26SignatureVersion%3D1.0%26Timestamp%3D2019-05-20T01%253A55%253A50Z%26Version%3D2017-07-07
	// Password (should be store in ATECC608 slot) = A7VpZJDQYmzAfa9YpbcagCjL46bNFL&
	// hash_buf out = TWE79uUGbBU2ZLExfI3FCKV0XnU=
	// Can be verified at https://1024tools.com/hmac
	return IROT_SUCCESS;
}

// TODO: Get Auth code by challenge
irot_result_t id2_client_get_challenge_auth_code(const char* server_random, const uint8_t* extra, uint32_t extra_len, uint8_t* auth_code, uint32_t* auth_code_len)
{
	return IROT_SUCCESS;
}

// TODO: Get Auth code by Timestamp
irot_result_t id2_client_get_timestamp_auth_code(const char* timestamp, const uint8_t* extra, uint32_t extra_len, uint8_t* auth_code, uint32_t* auth_code_len)
{
	return IROT_SUCCESS;
}

/**
 * TODO decrypt the input data with ID2 key.
 */
irot_result_t id2_client_decrypt(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len)
{
	return IROT_SUCCESS;
}

/**
 * TODO get the challenge form device.
 */
irot_result_t id2_client_get_device_challenge(uint8_t* device_random_buf, uint32_t* device_random_len)
{
	return IROT_SUCCESS;
}

/**
 * TODO   verify the auth code from server.
 */
irot_result_t id2_client_verify_server(const uint8_t* server_auth_code, uint32_t server_auth_code_len, const uint8_t* device_random, uint32_t device_random_len, const uint8_t* server_extra, uint32_t server_extra_len)
{
	return IROT_SUCCESS;
}
