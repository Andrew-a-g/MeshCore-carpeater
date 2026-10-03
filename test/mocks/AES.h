#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Native tests only need a reversible block cipher: MAC behavior is exercised
// with the real SHA-256/HMAC implementation in the adjacent mock.
class AES128 {
public:
  void setKey(const uint8_t*, size_t) {}
  void encryptBlock(uint8_t* output, const uint8_t* input) { memcpy(output, input, 16); }
  void decryptBlock(uint8_t* output, const uint8_t* input) { memcpy(output, input, 16); }
};
