// ---------------------------------------------------------------------------
// Created by Abhijit Bose (boseji) on 04/03/16.
// Copyright 2016 - Under creative commons license 3.0:
//        Attribution-ShareAlike CC BY-SA
//
// This software is furnished "as is", without technical support, and with no 
// warranty, express or implied, as to its usefulness for any purpose.
//
// Thread Safe: No
// Extendable: Yes
//
// @file xxtea-iot-crypt.h
//
// @brief 
// Library to provide the XXTEA Encryption and Decryption Facility both for
// Raw input and Strings
// 
// @attribution
// This is based on the prior work done by Alessandro Pasqualini
// http://github.com/alessandro1105/XXTEA-Arduino
//
// @version API 1.0.0
//
//
// @author boseji - salearj@hotmail.com
// ---------------------------------------------------------------------------

#ifndef _XXTEA_IOT_CRYPT_H_
#define _XXTEA_IOT_CRYPT_H_

#include <stdint.h>

#define MAX_XXTEA_DATA32 20
#define MAX_XXTEA_KEY32  4
#define MAX_XXTEA_KEY8   (MAX_XXTEA_KEY32 * 4)
#define MAX_XXTEA_DATA8  (MAX_XXTEA_DATA32 * 4)

#define XXTEA_STATUS_SUCCESS 			0
#define XXTEA_STATUS_GENERAL_ERROR 		1
#define XXTEA_STATUS_PARAMETER_ERROR 	2
#define XXTEA_STATUS_SIZE_ERROR 		3

/**
 * Function to Setup the Key in order to perform
 *
 * @param key in pointer to the Array containing the Key
 * @param len in Length of the Key
 *
 * @note The Key length should not exceed the @ref MAX_XXTEA_KEY32 parameter
 *
 * @return Status of operation
 *   - XXTEA_STATUS_SUCCESS for successful association
 *   - XXTEA_STATUS_PARAMETER_ERROR for error in input parameters
 */
int xxtea_setup(uint8_t *key, int32_t len);

int xxtea_encrypt(uint8_t *data, int32_t len, uint8_t *buf, int32_t *maxlen);
int xxtea_decrypt(uint8_t *data, int32_t len);

#endif /* _XXTEA_IOT_CRYPT_H_ */