#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Small SHA-256/HMAC implementation for native tests. It mirrors the subset of
// the Arduino Crypto API used by Utils.cpp.
class SHA256 {
  uint32_t state[8];
  uint64_t bitLength;
  uint8_t block[64];
  size_t blockLength;
  uint8_t hmacKey[64];
  bool hmacActive;

  static uint32_t rotate(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

  void transform(const uint8_t* data) {
    static const uint32_t k[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
      0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
      0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
      0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
      0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
      0xc67178f2};
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = (uint32_t(data[i * 4]) << 24) | (uint32_t(data[i * 4 + 1]) << 16) |
             (uint32_t(data[i * 4 + 2]) << 8) | data[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = rotate(w[i - 15], 7) ^ rotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = rotate(w[i - 2], 17) ^ rotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
      uint32_t s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = h + s1 + ch + k[i] + w[i];
      uint32_t s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t t2 = s0 + maj;
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
  }

  void reset() {
    static const uint32_t initial[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(state, initial, sizeof(state));
    bitLength = 0;
    blockLength = 0;
  }

  void finish(uint8_t hash[32]) {
    uint64_t totalBits = bitLength + blockLength * 8;
    block[blockLength++] = 0x80;
    if (blockLength > 56) {
      while (blockLength < 64) block[blockLength++] = 0;
      transform(block);
      blockLength = 0;
    }
    while (blockLength < 56) block[blockLength++] = 0;
    for (int i = 7; i >= 0; i--) block[blockLength++] = totalBits >> (i * 8);
    transform(block);
    for (int i = 0; i < 8; i++) {
      hash[i * 4] = state[i] >> 24;
      hash[i * 4 + 1] = state[i] >> 16;
      hash[i * 4 + 2] = state[i] >> 8;
      hash[i * 4 + 3] = state[i];
    }
  }

public:
  SHA256() : hmacActive(false) { reset(); }

  void update(const void* data, size_t len) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    while (len--) {
      block[blockLength++] = *bytes++;
      if (blockLength == 64) {
        transform(block);
        bitLength += 512;
        blockLength = 0;
      }
    }
  }

  void finalize(uint8_t* hash, size_t hashLen) {
    uint8_t full[32];
    finish(full);
    if (hashLen > sizeof(full)) hashLen = sizeof(full);
    memcpy(hash, full, hashLen);
  }

  void resetHMAC(const uint8_t* key, size_t keyLen) {
    memset(hmacKey, 0, sizeof(hmacKey));
    if (keyLen > sizeof(hmacKey)) {
      SHA256 digest;
      digest.update(key, keyLen);
      digest.finalize(hmacKey, 32);
    } else {
      memcpy(hmacKey, key, keyLen);
    }
    reset();
    uint8_t inner[64];
    for (int i = 0; i < 64; i++) inner[i] = hmacKey[i] ^ 0x36;
    update(inner, sizeof(inner));
    hmacActive = true;
  }

  void finalizeHMAC(const uint8_t*, size_t, uint8_t* hash, size_t hashLen) {
    uint8_t innerHash[32];
    finish(innerHash);
    reset();
    uint8_t outer[64];
    for (int i = 0; i < 64; i++) outer[i] = hmacKey[i] ^ 0x5c;
    update(outer, sizeof(outer));
    update(innerHash, sizeof(innerHash));
    finalize(hash, hashLen);
    hmacActive = false;
  }
};
