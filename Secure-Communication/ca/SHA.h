#ifndef SHA_H
#define SHA_H

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>


namespace SHA {
const uint32_t k[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

#define rotate_r(val, bits) (val >> bits | val << (32 - bits))

#define choice(x, y, z) (x & y) ^ (~x & z)

#define majority(x, y, z) (x & y) ^ (x & z) ^ (y & z)

#define sigma0(x) rotate_r(x, 2) ^ rotate_r(x, 13) ^ rotate_r(x, 22)

#define sigma1(x) rotate_r(x, 6) ^ rotate_r(x, 11) ^ rotate_r(x, 25)

#define gamma0(x) rotate_r(x, 7) ^ rotate_r(x, 18) ^ (x >> 3)

#define gamma1(x) rotate_r(x, 17) ^ rotate_r(x, 19) ^ (x >> 10)

std::vector<uint8_t> stringToBytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string bytesToString(const std::vector<uint8_t>& hash) {
    char res_hash[64];
    const char* alp = "0123456789abcdef";
    for (int i = 0; i < 32; ++i){
        uint8_t c = ((const uint8_t*)hash.data())[i];
        res_hash[i*2] = alp[c >> 4];
        res_hash[i*2 + 1] = alp[c & 15];
    }

    return std::string(res_hash, 64);
}

std::vector<uint8_t> padMessage(const std::vector<uint8_t>& message) {
    std::vector<uint8_t> padded = message;
    padded.push_back(0x80);
    while ((padded.size() % 64) != 56) {
        padded.push_back(0x00);
    }
    uint64_t messageBits = message.size() * 8;
    for (int i = 7; i >= 0; --i) {
        padded.push_back((messageBits >> (i * 8)) & 0xFF);
    }
    return padded;
}

void sha256(const std::vector<uint8_t>& input, std::vector<uint8_t>& hash) {
    uint32_t h[8] = {
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19
    };

    std::vector<uint8_t> paddedMessage = padMessage(input);

    for (size_t chunkOffset = 0; chunkOffset < paddedMessage.size(); chunkOffset += 64) {
        uint32_t w[64];

        for (int i = 0; i < 16; ++i) {
            w[i] = (paddedMessage[chunkOffset + i * 4] << 24) |
                   (paddedMessage[chunkOffset + i * 4 + 1] << 16) |
                   (paddedMessage[chunkOffset + i * 4 + 2] << 8) |
                   (paddedMessage[chunkOffset + i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            uint32_t g0 = gamma0(w[i - 15]);
            uint32_t g1 = gamma1(w[i - 2]);
            w[i] = g1 + w[i - 7] + g0 + w[i - 16];
        }

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t h0 = h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = sigma1(e);
            uint32_t ch = choice(e,f,g);
            uint32_t S0 = sigma0(a);
            uint32_t maj = majority(a,b,c);
            uint32_t t1 = h0 + S1 + ch + k[i] + w[i];
            uint32_t t2 = S0 + maj;

            h0 = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;

        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h0;
    }

    hash.clear();
    hash.resize(32);
    for (int i = 0; i < 8; i++) {
        hash[i*4] = (h[i] >> 24) & 255;
        hash[i*4 + 1] = (h[i] >> 16) & 255;
        hash[i*4 + 2] = (h[i] >> 8) & 255;
        hash[i*4 + 3] = h[i] & 255;
    }
}

std::string sha256(const std::string& input) {

    std::vector<uint8_t> messageBytes = stringToBytes(input);
    std::vector<uint8_t> hash;
    sha256(messageBytes, hash);
    return bytesToString(hash);
}


#undef rotate_r
#undef choice
#undef majority
#undef sigma0
#undef sigma1
#undef gamma0
#undef gamma1
}

#endif // SHA_H
