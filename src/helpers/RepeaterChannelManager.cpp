#include "RepeaterChannelManager.h"

#include <Utils.h>
#include <ctype.h>
#include <string.h>

namespace {
const uint8_t POLICY_MAGIC[] = {'R', 'C', 'D', 'P'};
const uint8_t POLICY_VERSION = 1;

uint32_t policyCrc32(const uint8_t* data, size_t length) {
  uint32_t crc = 0xFFFFFFFFU;
  for (size_t i = 0; i < length; i++) {
    crc ^= data[i];
    for (uint8_t bit = 0; bit < 8; bit++) {
      crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U)));
    }
  }
  return ~crc;
}

bool validNameChar(char c) {
  return isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.';
}
} // namespace

RepeaterChannelManager::RepeaterChannelManager() {
  memset(seen, 0, sizeof(seen));
  memset(denied, 0, sizeof(denied));
}

bool RepeaterChannelManager::derivePublicChannel(const char* name, uint8_t key[CIPHER_KEY_SIZE],
                                                  uint8_t* hash) {
  if (name == NULL || key == NULL || hash == NULL || name[0] != '#') return false;
  size_t len = strlen(name);
  if (len < 2 || len >= REPEATER_CHANNEL_NAME_SIZE) return false;
  for (size_t i = 1; i < len; i++) {
    if (!validNameChar(name[i])) return false;
  }
  mesh::Utils::sha256(key, CIPHER_KEY_SIZE, reinterpret_cast<const uint8_t*>(name), len);
  mesh::Utils::sha256(hash, 1, key, CIPHER_KEY_SIZE);
  return true;
}

void RepeaterChannelManager::observe(uint8_t hash, uint32_t now) {
  int empty = -1;
  int oldest = 0;
  for (int i = 0; i < MAX_TRACKED_CHANNELS; i++) {
    if (seen[i].occupied && seen[i].hash == hash) {
      if (seen[i].count != UINT16_MAX) seen[i].count++;
      seen[i].lastSeen = now;
      return;
    }
    if (!seen[i].occupied && empty < 0) empty = i;
    if (seen[i].lastSeen < seen[oldest].lastSeen) oldest = i;
  }
  int index = empty >= 0 ? empty : oldest;
  seen[index].hash = hash;
  seen[index].count = 1;
  seen[index].lastSeen = now;
  seen[index].occupied = true;
}

void RepeaterChannelManager::clearSeen() {
  memset(seen, 0, sizeof(seen));
}

size_t RepeaterChannelManager::getSeenCount() const {
  size_t count = 0;
  for (int i = 0; i < MAX_TRACKED_CHANNELS; i++) {
    if (seen[i].occupied) count++;
  }
  return count;
}

bool RepeaterChannelManager::getSeen(size_t orderedIndex, SeenChannel* result) const {
  if (result == NULL || orderedIndex >= getSeenCount()) return false;
  bool selected[MAX_TRACKED_CHANNELS] = {};
  int best = -1;
  for (size_t rank = 0; rank <= orderedIndex; rank++) {
    best = -1;
    for (int i = 0; i < MAX_TRACKED_CHANNELS; i++) {
      if (!seen[i].occupied || selected[i]) continue;
      if (best < 0 || seen[i].lastSeen > seen[best].lastSeen ||
          (seen[i].lastSeen == seen[best].lastSeen && seen[i].hash < seen[best].hash)) {
        best = i;
      }
    }
    if (best < 0) return false;
    selected[best] = true;
  }
  *result = seen[best];
  return true;
}

RepeaterChannelManager::AddResult RepeaterChannelManager::addDenied(const char* name,
                                                                     DeniedChannel* result) {
  uint8_t key[CIPHER_KEY_SIZE];
  uint8_t hash;
  if (!derivePublicChannel(name, key, &hash)) return ADD_INVALID;
  int empty = -1;
  for (int i = 0; i < MAX_DENIED_CHANNELS; i++) {
    if (denied[i].occupied && strcmp(denied[i].name, name) == 0) {
      if (result) *result = denied[i];
      return ADD_EXISTS;
    }
    if (!denied[i].occupied && empty < 0) empty = i;
  }
  if (empty < 0) return ADD_FULL;
  memset(&denied[empty], 0, sizeof(denied[empty]));
  strcpy(denied[empty].name, name);
  memcpy(denied[empty].key, key, sizeof(key));
  denied[empty].hash = hash;
  denied[empty].occupied = true;
  if (result) *result = denied[empty];
  return ADD_OK;
}

RepeaterChannelManager::RemoveResult RepeaterChannelManager::removeDenied(const char* name) {
  uint8_t key[CIPHER_KEY_SIZE];
  uint8_t hash;
  if (!derivePublicChannel(name, key, &hash)) return REMOVE_INVALID;
  for (int i = 0; i < MAX_DENIED_CHANNELS; i++) {
    if (denied[i].occupied && strcmp(denied[i].name, name) == 0) {
      memset(&denied[i], 0, sizeof(denied[i]));
      return REMOVE_OK;
    }
  }
  return REMOVE_NOT_FOUND;
}

void RepeaterChannelManager::clearDenied() {
  memset(denied, 0, sizeof(denied));
}

size_t RepeaterChannelManager::getDeniedCount() const {
  size_t count = 0;
  for (int i = 0; i < MAX_DENIED_CHANNELS; i++) {
    if (denied[i].occupied) count++;
  }
  return count;
}

bool RepeaterChannelManager::getDenied(size_t orderedIndex, DeniedChannel* result) const {
  if (result == NULL) return false;
  for (int i = 0; i < MAX_DENIED_CHANNELS; i++) {
    if (!denied[i].occupied) continue;
    if (orderedIndex == 0) {
      *result = denied[i];
      return true;
    }
    orderedIndex--;
  }
  return false;
}

const char* RepeaterChannelManager::deniedNameForHash(uint8_t hash) const {
  for (int i = 0; i < MAX_DENIED_CHANNELS; i++) {
    if (denied[i].occupied && denied[i].hash == hash) return denied[i].name;
  }
  return NULL;
}

bool RepeaterChannelManager::shouldDeny(const mesh::Packet* packet, const char** matchedName) const {
  if (matchedName) *matchedName = NULL;
  if (packet == NULL) return false;
  uint8_t type = packet->getPayloadType();
  if (type != PAYLOAD_TYPE_GRP_TXT && type != PAYLOAD_TYPE_GRP_DATA) return false;
  if (packet->payload_len < 1 + CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE) return false;

  uint8_t scratch[MAX_PACKET_PAYLOAD];
  for (int i = 0; i < MAX_DENIED_CHANNELS; i++) {
    if (!denied[i].occupied || denied[i].hash != packet->payload[0]) continue;
    uint8_t secret[PUB_KEY_SIZE] = {};
    memcpy(secret, denied[i].key, CIPHER_KEY_SIZE);
    int len = mesh::Utils::MACThenDecrypt(secret, scratch, &packet->payload[1],
                                          packet->payload_len - 1);
    if (len > 0) {
      if (matchedName) *matchedName = denied[i].name;
      return true;
    }
  }
  return false;
}

size_t RepeaterChannelManager::serializePolicy(uint8_t* dest, size_t capacity) const {
  size_t count = getDeniedCount();
  size_t length = 10 + count * REPEATER_CHANNEL_NAME_SIZE;
  if (dest == NULL || capacity < length) return 0;
  memcpy(dest, POLICY_MAGIC, sizeof(POLICY_MAGIC));
  dest[4] = POLICY_VERSION;
  dest[5] = static_cast<uint8_t>(count);
  size_t offset = 6;
  DeniedChannel entry;
  for (size_t i = 0; i < count; i++) {
    getDenied(i, &entry);
    memset(&dest[offset], 0, REPEATER_CHANNEL_NAME_SIZE);
    strcpy(reinterpret_cast<char*>(&dest[offset]), entry.name);
    offset += REPEATER_CHANNEL_NAME_SIZE;
  }
  const uint32_t crc = policyCrc32(dest, offset);
  dest[offset++] = static_cast<uint8_t>(crc);
  dest[offset++] = static_cast<uint8_t>(crc >> 8);
  dest[offset++] = static_cast<uint8_t>(crc >> 16);
  dest[offset] = static_cast<uint8_t>(crc >> 24);
  return length;
}

bool RepeaterChannelManager::deserializePolicy(const uint8_t* src, size_t length) {
  clearDenied();
  if (src == NULL || length < 10 || memcmp(src, POLICY_MAGIC, sizeof(POLICY_MAGIC)) != 0 ||
      src[4] != POLICY_VERSION || src[5] > MAX_DENIED_CHANNELS) {
    return false;
  }
  const size_t recordsLength = 6 + static_cast<size_t>(src[5]) * REPEATER_CHANNEL_NAME_SIZE;
  if (length != recordsLength + 4) return false;
  const uint32_t storedCrc = static_cast<uint32_t>(src[recordsLength]) |
                             (static_cast<uint32_t>(src[recordsLength + 1]) << 8) |
                             (static_cast<uint32_t>(src[recordsLength + 2]) << 16) |
                             (static_cast<uint32_t>(src[recordsLength + 3]) << 24);
  if (storedCrc != policyCrc32(src, recordsLength)) return false;

  RepeaterChannelManager loaded;
  size_t offset = 6;
  for (int i = 0; i < src[5]; i++, offset += REPEATER_CHANNEL_NAME_SIZE) {
    const char* name = reinterpret_cast<const char*>(&src[offset]);
    const void* terminator = memchr(name, 0, REPEATER_CHANNEL_NAME_SIZE);
    if (terminator == NULL) return false;
    size_t nameLength = static_cast<const char*>(terminator) - name;
    for (size_t j = nameLength + 1; j < REPEATER_CHANNEL_NAME_SIZE; j++) {
      if (src[offset + j] != 0) return false;
    }
    if (loaded.addDenied(name) != ADD_OK) return false;
  }
  memcpy(denied, loaded.denied, sizeof(denied));
  return true;
}
