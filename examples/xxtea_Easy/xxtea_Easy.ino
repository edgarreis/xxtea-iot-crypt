/*

  Easy to Use example of xxtea-iot-crypt Library

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

  String keybuf = F("Hello Password");
  Serial.print(F(" Password : "));  
  Serial.println(keybuf);
  
  // Setup the Key - Once
  if(!xxtea.setKey(keybuf))
  {
    Serial.println(" Assignment Failed!");
    return;
  }
  
  String plaintext = F("Hi There we can work with this");
  Serial.print(" Plain Text: ");
  Serial.println(plaintext);
  
  // Perform Encryption on the Data
  String result = xxtea.encrypt(plaintext);
  if(result == F("-FAIL-"))
  {
    Serial.println(" Encryption Failed!");
    return;
  }
  else
  {
    Serial.print(F(" Encrypted Data: "));
    Serial.println(result);
  }
  
  // Perform Decryption
  String result1 = xxtea.decrypt(result);
  if(result1 == F("-FAIL-"))
  {
    Serial.println(" Decryption Failed!");
    return;
  }
  else
  {
    Serial.print(F(" Decrypted Data: "));
    Serial.println(result1);
  }
  delay(1000);
}
