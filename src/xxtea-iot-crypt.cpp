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
// @file xxtea-iot-crypt.cpp
//
// @brief 
// Library to provide the XXTEA Encryption and Decryption Facility both for
// Raw input and Strings
// 
// @version API 1.0.0
//
//
// @author boseji - salearj@hotmail.com
// ---------------------------------------------------------------------------

#include "xxtea-iot-crypt.h"

#include "core/xxtea_internal.h"

#include <string.h>

static uint32_t xxtea_data[MAX_XXTEA_DATA32];
static uint32_t xxtea_key[MAX_XXTEA_KEY32];

int xxtea_setup(uint8_t *key, int32_t len)
{
  int ret = XXTEA_STATUS_GENERAL_ERROR;
  int i;
  do{
    if(key == NULL || len <= 0 || len > MAX_XXTEA_KEY8)
    {
      ret = XXTEA_STATUS_PARAMETER_ERROR;
      break;
    }
    // Initialize the Key
    memset((void *)xxtea_key, 0, MAX_XXTEA_KEY8);
    // Copy the Key from Buffer
    memcpy((void *)xxtea_key,(const void *)key,len);
    ret = XXTEA_STATUS_SUCCESS;
  }while(0);
  return ret;
}

int xxtea_encrypt(uint8_t *data, int32_t len, uint8_t *buf, int32_t *maxlen)
{
  int ret = XXTEA_STATUS_GENERAL_ERROR;
  int i;
  int32_t l;
  do{
    if(data == NULL || len <= 0 || len > MAX_XXTEA_DATA8 ||
      buf == NULL || *maxlen <= 0 || *maxlen < len)
    {
      ret = XXTEA_STATUS_PARAMETER_ERROR;
      break;
    }
    // Calculate the Length neded for the 32bit Buffer
    l = len/4;
    if(len % 4) l++;
    // Check if More than exptected space is needed
    if(l > MAX_XXTEA_DATA32 || *maxlen < (l * 4))
    {
      ret = XXTEA_STATUS_SIZE_ERROR;
      break;
    }
    // Initialize the Data
    memset((void *)xxtea_data, 0, MAX_XXTEA_DATA8);
    memcpy((void *)xxtea_data, (const void *)data, len);
    // Performn Encryption
    dtea_fn(xxtea_data, l, (const uint32_t *)xxtea_key);
    // Copy Encrypted Data back to buffer
    memcpy((void *)buf, (const void *)xxtea_data, (l*4));
    // Asign the Length
    *maxlen = l*4;
    ret = XXTEA_STATUS_SUCCESS;
  }while(0);
  return ret;
}

int xxtea_decrypt(uint8_t *data, int32_t len)
{
  int ret = XXTEA_STATUS_GENERAL_ERROR;
  int i;
  int32_t l;
  do {
    if(data == NULL || len <= 0 || (len%4) != 0)
    {
      ret = XXTEA_STATUS_PARAMETER_ERROR;
      break;
    }
    if(len > MAX_XXTEA_DATA8)
    {
      ret = XXTEA_STATUS_SIZE_ERROR;
      break;
    }
    // Copy the Data into Processing Array
    memset((void *)xxtea_data, 0, MAX_XXTEA_DATA8);
    memcpy((void *)xxtea_data, (const void *)data, len);
    // Get the Actual Size in 32bits - Negative for Decryption
    l = -(len / 4);
    // Performn Decryption
    dtea_fn(xxtea_data, l, (const uint32_t *)xxtea_key);
    // Copy Encrypted Data back to buffer
    memcpy((void *)data, (const void *)xxtea_data, len);
    ret = XXTEA_STATUS_SUCCESS;
  }while(0);
  return ret;
}

