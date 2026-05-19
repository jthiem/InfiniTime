#include "displayapp/screens/TOTP.h"
#include <lvgl/lvgl.h>
#include <cstddef>
#include <cstdint>
#include <cstring>

using namespace Pinetime::Applications::Screens;

namespace {
constexpr char kDummySecretBase64[] = "QUJDREVGR0hJSktMTU5PVQ=="; // "ABCDEFGHIJKLMNOP" in base64

inline uint32_t RotateLeft(uint32_t value, unsigned bits) {
  return (value << bits) | (value >> (32 - bits));
}

bool Base64Decode(const char* source, std::uint8_t* destination, size_t& destinationSize) {
  static const int8_t decodeTable[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  };

  const char* src = source;
  std::uint8_t* dst = destination;
  size_t outLen = 0;
  uint32_t buffer = 0;
  int bitsCollected = 0;

  while (*src != '\0') {
    const int8_t value = decodeTable[static_cast<unsigned char>(*src)];
    if (value >= 0) {
      buffer = (buffer << 6) | static_cast<uint32_t>(value);
      bitsCollected += 6;
      if (bitsCollected >= 8) {
        bitsCollected -= 8;
        if (outLen >= destinationSize) {
          return false;
        }
        dst[outLen++] = static_cast<uint8_t>((buffer >> bitsCollected) & 0xFFu);
      }
    } else if (*src == '=') {
      break;
    }
    ++src;
  }

  destinationSize = outLen;
  return true;
}

void Sha1(const std::uint8_t* data, size_t length, std::uint8_t digest[20]) {
  uint32_t h[5] = {
    0x67452301u,
    0xEFCDAB89u,
    0x98BADCFEu,
    0x10325476u,
    0xC3D2E1F0u
  };

  auto processBlock = [&](const std::uint8_t block[64]) {
    uint32_t w[80];
    for (unsigned i = 0; i < 16; ++i) {
      w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
             (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
             (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
             static_cast<uint32_t>(block[i * 4 + 3]);
    }
    for (unsigned i = 16; i < 80; ++i) {
      w[i] = RotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];

    for (unsigned i = 0; i < 80; ++i) {
      uint32_t f;
      uint32_t k;
      if (i < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999u;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1u;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDCu;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6u;
      }
      const uint32_t temp = RotateLeft(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = RotateLeft(b, 30);
      b = a;
      a = temp;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  };

  uint64_t bitLength = static_cast<uint64_t>(length) * 8ull;
  size_t fullBlocks = length / 64;
  for (size_t i = 0; i < fullBlocks; ++i) {
    processBlock(data + (i * 64));
  }

  uint8_t block[64];
  const size_t remaining = length - fullBlocks * 64;
  std::memcpy(block, data + fullBlocks * 64, remaining);
  block[remaining] = 0x80;
  if (remaining + 1 < 64) {
    std::memset(block + remaining + 1, 0, 63 - remaining);
  }

  if (remaining >= 56) {
    processBlock(block);
    std::memset(block, 0, 56);
  } else {
    std::memset(block + remaining + 1, 0, 56 - remaining - 1);
  }

  block[56] = static_cast<uint8_t>((bitLength >> 56) & 0xFFu);
  block[57] = static_cast<uint8_t>((bitLength >> 48) & 0xFFu);
  block[58] = static_cast<uint8_t>((bitLength >> 40) & 0xFFu);
  block[59] = static_cast<uint8_t>((bitLength >> 32) & 0xFFu);
  block[60] = static_cast<uint8_t>((bitLength >> 24) & 0xFFu);
  block[61] = static_cast<uint8_t>((bitLength >> 16) & 0xFFu);
  block[62] = static_cast<uint8_t>((bitLength >> 8) & 0xFFu);
  block[63] = static_cast<uint8_t>(bitLength & 0xFFu);
  processBlock(block);

  for (unsigned i = 0; i < 5; ++i) {
    digest[i * 4] = static_cast<std::uint8_t>((h[i] >> 24) & 0xFFu);
    digest[i * 4 + 1] = static_cast<std::uint8_t>((h[i] >> 16) & 0xFFu);
    digest[i * 4 + 2] = static_cast<std::uint8_t>((h[i] >> 8) & 0xFFu);
    digest[i * 4 + 3] = static_cast<std::uint8_t>(h[i] & 0xFFu);
  }
}

void HmacSha1(const std::uint8_t* key, size_t keyLength, const std::uint8_t* message, size_t messageLength, std::uint8_t output[20]) {
  constexpr size_t blockSize = 64;
  std::uint8_t keyBlock[blockSize];
  std::memset(keyBlock, 0, blockSize);

  if (keyLength > blockSize) {
    Sha1(key, keyLength, keyBlock);
  } else {
    std::memcpy(keyBlock, key, keyLength);
  }

  std::uint8_t oKeyPad[blockSize];
  std::uint8_t iKeyPad[blockSize];
  for (size_t i = 0; i < blockSize; ++i) {
    oKeyPad[i] = keyBlock[i] ^ 0x5Cu;
    iKeyPad[i] = keyBlock[i] ^ 0x36u;
  }

  std::uint8_t inner[20];
  std::uint8_t innerData[blockSize + 8];
  std::memcpy(innerData, iKeyPad, blockSize);
  std::memcpy(innerData + blockSize, message, messageLength);
  Sha1(innerData, blockSize + messageLength, inner);

  std::uint8_t outerData[blockSize + 20];
  std::memcpy(outerData, oKeyPad, blockSize);
  std::memcpy(outerData + blockSize, inner, 20);
  Sha1(outerData, blockSize + 20, output);
}

uint32_t CalculateTotpCode(const std::uint8_t* secret, size_t secretLength, uint64_t counter) {
  std::uint8_t counterBytes[8];
  for (int i = 7; i >= 0; --i) {
    counterBytes[i] = static_cast<std::uint8_t>(counter & 0xFFull);
    counter >>= 8;
  }

  std::uint8_t hmac[20];
  HmacSha1(secret, secretLength, counterBytes, sizeof(counterBytes), hmac);

  const uint8_t offset = hmac[19] & 0x0Fu;
  uint32_t code = ((static_cast<uint32_t>(hmac[offset]) & 0x7Fu) << 24) |
                  (static_cast<uint32_t>(hmac[offset + 1]) << 16) |
                  (static_cast<uint32_t>(hmac[offset + 2]) << 8) |
                  static_cast<uint32_t>(hmac[offset + 3]);
  return code % 1000000u;
}
} // namespace

TOTP::TOTP() {
  title = lv_label_create(lv_scr_act(), nullptr);
  lv_label_set_text_static(title, "TOTP");
  lv_obj_align(title, nullptr, LV_ALIGN_IN_TOP_MID, 0, 12);

  labelCode = lv_label_create(lv_scr_act(), nullptr);
  lv_label_set_text_static(labelCode, "000000");
  lv_obj_align(labelCode, nullptr, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_local_text_font(labelCode, LV_LABEL_PART_MAIN, LV_STATE_DEFAULT, &jetbrains_mono_42);

  labelTimer = lv_label_create(lv_scr_act(), nullptr);
  lv_label_set_text_static(labelTimer, "30");
  lv_obj_align(labelTimer, nullptr, LV_ALIGN_IN_TOP_RIGHT, -8, 12);

  taskRefresh = lv_task_create(RefreshTaskCallback, 1000, LV_TASK_PRIO_MID, this);
  Refresh();
}

TOTP::~TOTP() {
  if (taskRefresh) {
    lv_task_del(taskRefresh);
  }
  lv_obj_clean(lv_scr_act());
}

void TOTP::Refresh() {
  const uint64_t seconds = lv_tick_get() / 1000ull;
  const uint32_t period = static_cast<uint32_t>(seconds / 30ull);
  const int remaining = static_cast<int>(30 - (seconds % 30ull));
  lv_label_set_text_fmt(labelTimer, "%02d", remaining == 30 ? 30 : remaining);

  std::uint8_t secret[32];
  size_t secretLength = sizeof(secret);
  Base64Decode(kDummySecretBase64, secret, secretLength);
  const uint32_t code = CalculateTotpCode(secret, secretLength, period);
  lv_label_set_text_fmt(labelCode, "%06u", code);
}