#include <gtest/gtest.h>

#include <Utils.h>
#include <helpers/RepeaterChannelManager.h>

#include <cstdio>
#include <cstring>

namespace {
mesh::Packet groupPacket(const char* name, uint8_t type = PAYLOAD_TYPE_GRP_TXT) {
  mesh::Packet packet;
  uint8_t key[CIPHER_KEY_SIZE];
  uint8_t hash;
  EXPECT_TRUE(RepeaterChannelManager::derivePublicChannel(name, key, &hash));
  uint8_t secret[PUB_KEY_SIZE] = {};
  memcpy(secret, key, sizeof(key));
  packet.header = (type << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD;
  packet.payload[0] = hash;
  const uint8_t data[] = {1, 2, 3, 4, 0, 'x'};
  packet.payload_len = 1 + mesh::Utils::encryptThenMAC(secret, &packet.payload[1], data, sizeof(data));
  return packet;
}
} // namespace

TEST(RepeaterChannelManagerTest, DerivesDocumentedPublicChannel) {
  uint8_t key[CIPHER_KEY_SIZE];
  uint8_t hash;
  ASSERT_TRUE(RepeaterChannelManager::derivePublicChannel("#test", key, &hash));
  const uint8_t expected[] = {0x9c, 0xd8, 0xfc, 0xf2, 0x2a, 0x47, 0x33, 0x3b,
                              0x59, 0x1d, 0x96, 0xa2, 0xb8, 0x48, 0xb7, 0x3f};
  EXPECT_EQ(0, memcmp(key, expected, sizeof(key)));
  EXPECT_EQ(0xD9, hash);
}

TEST(RepeaterChannelManagerTest, RejectsInvalidPublicChannelNames) {
  uint8_t key[CIPHER_KEY_SIZE], hash;
  EXPECT_FALSE(RepeaterChannelManager::derivePublicChannel("test", key, &hash));
  EXPECT_FALSE(RepeaterChannelManager::derivePublicChannel("#", key, &hash));
  EXPECT_FALSE(RepeaterChannelManager::derivePublicChannel("#bad name", key, &hash));
  EXPECT_FALSE(RepeaterChannelManager::derivePublicChannel("#bad!", key, &hash));
  EXPECT_FALSE(RepeaterChannelManager::derivePublicChannel(
      "#1234567890123456789012345678901", key, &hash));
}

TEST(RepeaterChannelManagerTest, TracksSortsSaturatesAndClearsSeenChannels) {
  RepeaterChannelManager manager;
  manager.observe(0x20, 10);
  manager.observe(0x10, 20);
  manager.observe(0x20, 30);
  ASSERT_EQ(2U, manager.getSeenCount());
  RepeaterChannelManager::SeenChannel seen;
  ASSERT_TRUE(manager.getSeen(0, &seen));
  EXPECT_EQ(0x20, seen.hash);
  EXPECT_EQ(2, seen.count);
  EXPECT_EQ(30U, seen.lastSeen);

  manager.addDenied("#test");
  manager.clearSeen();
  EXPECT_EQ(0U, manager.getSeenCount());
  EXPECT_EQ(1U, manager.getDeniedCount());
}

TEST(RepeaterChannelManagerTest, EvictsOldestSeenChannel) {
  RepeaterChannelManager manager;
  for (int i = 0; i < MAX_TRACKED_CHANNELS; i++) manager.observe(i, i + 1);
  manager.observe(0xEE, 1000);
  EXPECT_EQ(MAX_TRACKED_CHANNELS, manager.getSeenCount());
  bool foundOldest = false, foundNewest = false;
  RepeaterChannelManager::SeenChannel seen;
  for (size_t i = 0; manager.getSeen(i, &seen); i++) {
    foundOldest |= seen.hash == 0;
    foundNewest |= seen.hash == 0xEE;
  }
  EXPECT_FALSE(foundOldest);
  EXPECT_TRUE(foundNewest);
}

TEST(RepeaterChannelManagerTest, DeniesOnlyAuthenticatedGroupPackets) {
  RepeaterChannelManager manager;
  ASSERT_EQ(RepeaterChannelManager::ADD_OK, manager.addDenied("#test"));
  mesh::Packet packet = groupPacket("#test");
  const char* matched = nullptr;
  EXPECT_TRUE(manager.shouldDeny(&packet, &matched));
  ASSERT_NE(nullptr, matched);
  EXPECT_STREQ("#test", matched);

  packet.payload[1] ^= 1;
  EXPECT_FALSE(manager.shouldDeny(&packet));
  packet = groupPacket("#test");
  packet.payload_len = 3;
  EXPECT_FALSE(manager.shouldDeny(&packet));
  packet = groupPacket("#test");
  packet.header = (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD;
  EXPECT_FALSE(manager.shouldDeny(&packet));
  packet = groupPacket("#test");
  packet.header = (PAYLOAD_TYPE_GRP_TXT << PH_TYPE_SHIFT) | ROUTE_TYPE_DIRECT;
  EXPECT_TRUE(manager.shouldDeny(&packet));
}

TEST(RepeaterChannelManagerTest, HashCollisionWithInvalidMacIsAllowed) {
  RepeaterChannelManager manager;
  ASSERT_EQ(RepeaterChannelManager::ADD_OK, manager.addDenied("#test"));
  mesh::Packet packet = groupPacket("#other");
  packet.payload[0] = 0xD9;
  EXPECT_FALSE(manager.shouldDeny(&packet));
}

TEST(RepeaterChannelManagerTest, DenyMutationsAreExactBoundedAndIdempotent) {
  RepeaterChannelManager manager;
  EXPECT_EQ(RepeaterChannelManager::ADD_OK, manager.addDenied("#test"));
  EXPECT_EQ(RepeaterChannelManager::ADD_EXISTS, manager.addDenied("#test"));
  EXPECT_EQ(RepeaterChannelManager::REMOVE_NOT_FOUND, manager.removeDenied("#Test"));
  EXPECT_EQ(RepeaterChannelManager::REMOVE_OK, manager.removeDenied("#test"));
  for (int i = 0; i < MAX_DENIED_CHANNELS; i++) {
    char name[20];
    snprintf(name, sizeof(name), "#channel%d", i);
    EXPECT_EQ(RepeaterChannelManager::ADD_OK, manager.addDenied(name));
  }
  EXPECT_EQ(RepeaterChannelManager::ADD_FULL, manager.addDenied("#overflow"));
  EXPECT_EQ(MAX_DENIED_CHANNELS, manager.getDeniedCount());
}

TEST(RepeaterChannelManagerTest, PolicyRoundTripDoesNotPersistSeenState) {
  RepeaterChannelManager source;
  source.observe(0xD9, 42);
  source.addDenied("#test");
  source.addDenied("#another");
  uint8_t bytes[REPEATER_CHANNEL_POLICY_MAX_SIZE];
  size_t length = source.serializePolicy(bytes, sizeof(bytes));
  ASSERT_GT(length, 0U);

  RepeaterChannelManager loaded;
  ASSERT_TRUE(loaded.deserializePolicy(bytes, length));
  EXPECT_EQ(2U, loaded.getDeniedCount());
  EXPECT_EQ(0U, loaded.getSeenCount());
  RepeaterChannelManager::DeniedChannel entry;
  ASSERT_TRUE(loaded.getDenied(0, &entry));
  EXPECT_STREQ("#test", entry.name);
  EXPECT_EQ(0xD9, entry.hash);
}

TEST(RepeaterChannelManagerTest, CorruptPoliciesFailOpenToEmpty) {
  RepeaterChannelManager manager;
  manager.addDenied("#test");
  uint8_t valid[REPEATER_CHANNEL_POLICY_MAX_SIZE];
  size_t length = manager.serializePolicy(valid, sizeof(valid));

  uint8_t corrupt[REPEATER_CHANNEL_POLICY_MAX_SIZE];
  memcpy(corrupt, valid, length);
  corrupt[0] ^= 1;
  EXPECT_FALSE(manager.deserializePolicy(corrupt, length));
  EXPECT_EQ(0U, manager.getDeniedCount());

  memcpy(corrupt, valid, length);
  corrupt[4]++;
  EXPECT_FALSE(manager.deserializePolicy(corrupt, length));
  memcpy(corrupt, valid, length);
  corrupt[5] = MAX_DENIED_CHANNELS + 1;
  EXPECT_FALSE(manager.deserializePolicy(corrupt, length));
  EXPECT_FALSE(manager.deserializePolicy(valid, length - 1));

  memcpy(corrupt, valid, length);
  memset(&corrupt[6], 'x', REPEATER_CHANNEL_NAME_SIZE);
  EXPECT_FALSE(manager.deserializePolicy(corrupt, length));

  memcpy(corrupt, valid, length);
  corrupt[7] = ' ';
  EXPECT_FALSE(manager.deserializePolicy(corrupt, length));

  // A bit flip that leaves a syntactically valid name must also fail open.
  memcpy(corrupt, valid, length);
  corrupt[7] = 'u';
  EXPECT_FALSE(manager.deserializePolicy(corrupt, length));
  EXPECT_EQ(0U, manager.getDeniedCount());
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
