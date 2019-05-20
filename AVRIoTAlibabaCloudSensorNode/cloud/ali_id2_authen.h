/*
 * ali_id2_authen.h
 *
 * Created: 2019/5/17 10:34:30
 *  Author: A41547
 */ 


#ifndef ALI_ID2_AUTHEN_H_
#define ALI_ID2_AUTHEN_H_

#include <atmel_start.h>
// <s> ali id2 server
// <i> id2 server host address
// <id> mqtt_host
#define CFG_ALI_ID2_HOST "id2.cn-shanghai.aliyuncs.com"
	
//#define CFG_ALI_ID2_GET_RANDOM "ApiVersion=1.1.2&SignatureVersion=1.0&Action=GetServerRandom&Format=XML&SignatureNonce=b53e9e1b-bc61-4880-b3de-fdf2d53ad9d9&Version=2017-07-07&Id2=00FFFF00FFFFFF073EC5AC00&AccessKeyId=LTAIXQlg58OsZV6X&Signature=I2jQgmO8loJ330YmrmuLOcjZWj8%3D&SignatureMethod=HMAC-SHA1&RegionId=cn-shanghai&Timestamp=2019-05-19T13%3A44%3A00Z"
#define CFG_ALI_ID2_GET_RANDOM "ApiVersion=1.1.2&SignatureVersion=1.0&Action=GetServerRandom&Format=XML&SignatureNonce=6ad3b916-f8d5-4e0d-b8bb-a94bc34fc239&Version=2017-07-07&Id2=00FFFF00FFFFFF073EC5AC00&AccessKeyId=LTAIXQlg58OsZV6X&Signature=dw6JtKNoy2FNH7jwsDP3yZg%2FZh8%3D&SignatureMethod=HMAC-SHA1&RegionId=cn-shanghai&Timestamp=2019-05-19T14%3A20%3A19Z"

void connectID2(void);

#define ID2_CLIENT_VERSION_NUMBER   0x00000100

typedef enum
{
	IROT_SUCCESS                 = 0,  ///< The operation was successful.
	IROT_ERROR_GENERIC           = -1, ///< Non-specific casuse.
	IROT_ERROR_BAD_PARAMETERS    = -2, ///< Input parameters were invlid.
	IROT_ERROR_SHORT_BUFFER      = -3, ///< The supplied buffer is too short for the output.
	IROT_ERROR_EXCESS_DATA       = -4, ///< Too much data for the requested operation was passed.
	IROT_ERROR_OUT_OF_MEMORY     = -5, ///< System out of memory resources.
	IROT_ERROR_COMMUNICATION     = -7, ///< Communication error
	IROT_ERROR_NOT_SUPPORTED     = -8, ///< The request operation is valid but is not supported in this implementation.
	IROT_ERROR_NOT_IMPLEMENTED   = -9, ///< The requested operation should exist but is not yet implementation.
	IROT_ERROR_TIMEOUT			 = -10,///< Communication Timeout
	IROT_ERROR_ITEM_NOT_FOUND    = -11,///< Id2 is not exist
} irot_result_t;

#define ID2_ID_LEN                          24
#define ID2_MAX_SERVER_RANDOM_LEN           32
#define ID2_MAX_DEVICE_RANDOM_LEN           16
#define ID2_MAX_EXTRA_LEN                   512
#define ID2_MAX_CRYPTO_LEN                  4096
#define AUTH_CODE_BUF_LEN                   256

/**
 * @brief initialize the id2 client, must be called first before other ID2 client API.
 *
 * @return @see irot_result_t
 */
irot_result_t id2_client_init(void);

/**
 * @brief get the id2-client-sdk version number
 * @param[out] pversion     the version number for output
 *
 * @return @see irot_result_t
 */
irot_result_t id2_client_get_version(uint32_t* pversion);

/**
 * @brief get ID2 information
 *
 * @param[out] id   the ID2 buffer, buffer size must >= ID2_ID_LEN.
 * @param[inout]   len input with the ID2 buffer size, ouput the real data length.
 *
 * @return @see irot_result_t
 */
irot_result_t id2_client_get_id(uint8_t* id, uint32_t* len);

/**
 * @brief get the authentication code with the challenge mode.
 *
 * @param[in]  server_random     random data from ID2 server.
 * @param[in]  extra             extra data, optional data, no more than 512 bytes.
 * @param[in]  extra_len         length of extra data.
 * @param[out] auth_code         the auth code output buffer.
 * @param[inout] auth_code_len   input with the output buffer size, ouput the real data length.
 *
 * @return @see irot_result_t
 */
irot_result_t id2_client_get_challenge_auth_code(const char* server_random, const uint8_t* extra, uint32_t extra_len, uint8_t* auth_code, uint32_t* auth_code_len);

/**
 * @brief get the authentication code with timestamp mode.
 *
 * @param[in]  timestamp         the number of milliseconds since the Epoch, 1970-01-01 00:00:00 +0000 (UTC)
 * @param[in]  extra             extra data, optional data, no more than 512 bytes.
 * @param[in]  extra_len         length of extra data.
 * @param[out] auth_code         the auth code output buffer.
 * @param[inout] auth_code_len   input with the output buffer size, ouput the real data length.
 *
 * @return @see irot_result_t
 */
irot_result_t id2_client_get_timestamp_auth_code(const char* timestamp, const uint8_t* extra, uint32_t extra_len, uint8_t* auth_code, uint32_t* auth_code_len);

/**
 * @brief decrypt the input data with ID2 key.
 *
 * @param[in]  in               input data.
 * @param[in]  in_len           lenth of the input data, which must <= 4096 bytes.
 * @param[out] out              output buffer for decrypt data.
 * @param[inout] out_len        input with the output buffer size, ouput the real data length.
 *
 * @return @see irot_result_t
 */
irot_result_t id2_client_decrypt(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len);

/**
 * @brief get the challenge form device.
 *
 * @param[out] device_random_buf        output buffer for device challenge.
 * @param[inout] device_random_len      input with the output buffer size, ouput the real data length.
 *
 * @return @see irot_result_t
 */
irot_result_t id2_client_get_device_challenge(uint8_t* device_random_buf, uint32_t* device_random_len);

/**
 * @brief   verify the auth code from server.
 *
 * @param[in] server_auth_code       auth code of server.
 * @param[in] server_auth_code_len   auth code length.
 * @param[in] device_random          device challenge, may be NULL if the get_device_challenge has been called.
 * @param[in] device_random_len      the length of device challenge, must set to 0 if device_random is null.
 * @param[in] server_extra           extra data of server.
 * @param[in] server_extra_len       extra data length.
 *
 * @return @see irot_result_t
 */
irot_result_t id2_client_verify_server(const uint8_t* server_auth_code, uint32_t server_auth_code_len, const uint8_t* device_random, uint32_t device_random_len, const uint8_t* server_extra, uint32_t server_extra_len);


#endif /* ALI_ID2_AUTHEN_H_ */