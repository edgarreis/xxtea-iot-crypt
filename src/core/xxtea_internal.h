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
// @file xxtea_internal.h
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
#ifndef _XXTEA_INTERNAL_H_
#define _XXTEA_INTERNAL_H_

#include <stdint.h>

void dtea_fn(uint32_t *v, int32_t n, uint32_t const key[4]);

#endif /* _XXTEA_INTERNAL_H_ */