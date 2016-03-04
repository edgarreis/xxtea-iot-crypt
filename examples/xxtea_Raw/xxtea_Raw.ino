/*

  RAW Use example of xxtea-iot-crypt Library

  This example shows the calling convention for the various functions.

  For more information about this library please visit us at
  http://github.com/boseji/xxtea-iot-crypt

  Created by Abhijit Bose (boseji) on 04/03/16.
  Copyright 2016 - Under creative commons license 3.0:
        Attribution-ShareAlike CC BY-SA

  @version API 1.0.0
  @author boseji - salearj@hotmail.com

*/

#include <xxtea-iot-crypt.h>

void setup() {
  Serial.begin(115200);
}

void loop() {
  Serial.println();
  uint8_t keybuf[] = "Hello Password";
  uint8_t plaintext[] = "Hi There we can work with this";
  uint8_t buffer[200];
  int32_t len = 200, i;
  Serial.printf(" Password : %s\n", keybuf);
  // Setup the Key - Once
  if(xxtea_setup(keybuf, strlen((char *)keybuf)) != XXTEA_STATUS_SUCCESS)
  {
    Serial.println(" Assignment Failed!");
    return;
  }
  Serial.printf(" Plain Text: %s\n", plaintext);
  // Perform Encryption on the Data
  len = 200;  // - Initialize the Maximum buffer length
  if(xxtea_encrypt(plaintext, strlen((char*)plaintext), buffer, &len) !=
    XXTEA_STATUS_SUCCESS)
  {
    Serial.println(" Encryption Failed!");
    return;
  }
  else
  {
    Serial.print(" Encrypted Data: ");
    for(i = 0;i<len;i++)
      Serial.printf("0x%02X ", buffer[i]);
    Serial.println();
  }
  // Perform Decryption
  if(xxtea_decrypt(buffer, len) != XXTEA_STATUS_SUCCESS)
  {
    Serial.println(" Decryption Failed!");
    return;
  }
  else
  {
    Serial.printf(" Decrypted Data: %s\n", buffer);
  }
  delay(1000);
}
