#pragma once

#include <MeshCore.h>
#include <Packet.h>
#include <stddef.h>
#include <stdint.h>

#ifndef MAX_TRACKED_CHANNELS
#define MAX_TRACKED_CHANNELS 32
#endif

#ifndef MAX_DENIED_CHANNELS
#define MAX_DENIED_CHANNELS 16
#endif

#define REPEATER_CHANNEL_NAME_SIZE 32
#define REPEATER_CHANNEL_POLICY_MAX_SIZE (10 + MAX_DENIED_CHANNELS * REPEATER_CHANNEL_NAME_SIZE)

class RepeaterChannelManager {
public:
  struct SeenChannel {
    uint8_t hash;
    uint16_t count;
    uint32_t lastSeen;
    bool occupied;
  };

  struct DeniedChannel {
    char name[REPEATER_CHANNEL_NAME_SIZE];
    uint8_t key[CIPHER_KEY_SIZE];
    uint8_t hash;
    bool occupied;
  };

  enum AddResult { ADD_OK, ADD_EXISTS, ADD_INVALID, ADD_FULL };
  enum RemoveResult { REMOVE_OK, REMOVE_NOT_FOUND, REMOVE_INVALID };

  RepeaterChannelManager();

  static bool derivePublicChannel(const char* name, uint8_t key[CIPHER_KEY_SIZE], uint8_t* hash);
  static bool isValidGroupPacket(const mesh::Packet* packet);

  void observe(uint8_t hash, uint32_t now);
  void clearSeen();
  size_t getSeenCount() const;
  bool getSeen(size_t orderedIndex, SeenChannel* result) const;

  AddResult addDenied(const char* name, DeniedChannel* result = NULL);
  RemoveResult removeDenied(const char* name);
  void clearDenied();
  size_t getDeniedCount() const;
  bool getDenied(size_t orderedIndex, DeniedChannel* result) const;
  const char* deniedNameForHash(uint8_t hash) const;

  bool shouldDeny(const mesh::Packet* packet, const char** matchedName = NULL) const;

  size_t serializePolicy(uint8_t* dest, size_t capacity) const;
  bool deserializePolicy(const uint8_t* src, size_t length);

private:
  static bool deriveDenyTarget(const char* name, uint8_t key[CIPHER_KEY_SIZE], uint8_t* hash);

  SeenChannel seen[MAX_TRACKED_CHANNELS];
  DeniedChannel denied[MAX_DENIED_CHANNELS];
};
