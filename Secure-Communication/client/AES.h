#ifndef AES_H
#define AES_H

#include <cstdint>
#include <vector>

namespace AES {

#define Nb 4

#define Nk 8       //for 256 bit

#define Nr 14      //for 256 bit

#define blockBytesSz (size_t)(4 * Nb * sizeof(uint8_t))

static bool is_init = false;

const uint8_t sbox[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
     0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
     0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
     0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
     0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
     0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39,
     0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
     0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21,
     0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
     0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
     0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62,
     0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea,
     0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
     0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
     0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9,
     0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
     0xb0, 0x54, 0xbb, 0x16} };

const uint8_t inv_sbox[16][16] = {
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
     0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44,
     0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
     0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
     0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc,
     0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57,
     0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
     0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03,
     0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce,
     0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
     0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e,
     0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe,
     0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
     0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
     0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c,
     0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
     0x55, 0x21, 0x0c, 0x7d} };

static uint8_t gf_mul2[256];
static uint8_t gf_mul3[256];
static uint8_t gf_mul9[256];
static uint8_t gf_mul11[256];
static uint8_t gf_mul13[256];
static uint8_t gf_mul14[256];

void generate_gf_tables() {
    for (int i = 0; i < 256; ++i) {
        gf_mul2[i] = (i << 1) ^ ((i & 0x80) ? 0x1b : 0x00);
        gf_mul2[i] &= 0xFF;
        gf_mul3[i] = gf_mul2[i] ^ i;
    }

    for (int i = 0; i < 256; ++i) {
        gf_mul9[i] = gf_mul2[gf_mul2[gf_mul2[i]]] ^ i;
        gf_mul11[i] = gf_mul2[gf_mul2[gf_mul2[i]]] ^ gf_mul2[i] ^ i;
        gf_mul13[i] = gf_mul2[gf_mul2[gf_mul2[i]]] ^ gf_mul2[gf_mul2[i]] ^ i;
        gf_mul14[i] = gf_mul2[gf_mul2[gf_mul2[i]]] ^ gf_mul2[gf_mul2[i]] ^ gf_mul2[i];
    }
}

uint8_t xtime(uint8_t b)
{
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

void xorBlocks(const uint8_t* a, const uint8_t* b, uint8_t* c, int sz) {
    for (int i = 0; i < sz; i++) {
        c[i] = a[i] ^ b[i];
    }
}

void subWord(uint8_t* a) {
    int i;
    for (i = 0; i < 4; i++) {
        a[i] = sbox[a[i] / 16][a[i] % 16];
    }
}

void subBytes(uint8_t state[4][Nb]) {
    uint8_t t;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = sbox[t / 16][t % 16];
        }
    }
}

void invSubBytes(uint8_t state[4][Nb]) {
    uint8_t t;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}

void shiftRow(uint8_t state[4][Nb], int i, int n)
{
    uint8_t tmp[Nb];
    for (int j = 0; j < Nb; j++) {
        tmp[j] = state[i][(j + n) % Nb];
    }
    for (int j = 0; j < Nb; ++j) {
        state[i][j] = tmp[j];
    }
}

void shiftRows(uint8_t state[4][Nb]) {
    shiftRow(state, 1, 1);
    shiftRow(state, 2, 2);
    shiftRow(state, 3, 3);
}

void invShiftRows(uint8_t state[4][Nb]) {
    shiftRow(state, 1, Nb - 1);
    shiftRow(state, 2, Nb - 2);
    shiftRow(state, 3, Nb - 3);
}

void rotWord(uint8_t* a) {
    uint8_t c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

void xorWords(uint8_t* a, uint8_t* b, uint8_t* c) {
    for (int i = 0; i < 4; i++) {
        c[i] = a[i] ^ b[i];
    }
}

void mixColumns(uint8_t state[4][4]) {
    uint8_t tmp[4];
    for (int c = 0; c < 4; ++c) {
        tmp[0] = gf_mul2[state[0][c]] ^ gf_mul3[state[1][c]] ^ state[2][c] ^ state[3][c];
        tmp[1] = state[0][c] ^ gf_mul2[state[1][c]] ^ gf_mul3[state[2][c]] ^ state[3][c];
        tmp[2] = state[0][c] ^ state[1][c] ^ gf_mul2[state[2][c]] ^ gf_mul3[state[3][c]];
        tmp[3] = gf_mul3[state[0][c]] ^ state[1][c] ^ state[2][c] ^ gf_mul2[state[3][c]];

        for (int i = 0; i < 4; ++i) {
            state[i][c] = tmp[i];
        }
    }
}

void invMixColumns(uint8_t state[4][4]) {
    uint8_t tmp[4];
    for (int c = 0; c < 4; ++c) {
        tmp[0] = gf_mul14[state[0][c]] ^ gf_mul11[state[1][c]] ^ gf_mul13[state[2][c]] ^ gf_mul9[state[3][c]];
        tmp[1] = gf_mul9[state[0][c]] ^ gf_mul14[state[1][c]] ^ gf_mul11[state[2][c]] ^ gf_mul13[state[3][c]];
        tmp[2] = gf_mul13[state[0][c]] ^ gf_mul9[state[1][c]] ^ gf_mul14[state[2][c]] ^ gf_mul11[state[3][c]];
        tmp[3] = gf_mul11[state[0][c]] ^ gf_mul13[state[1][c]] ^ gf_mul9[state[2][c]] ^ gf_mul14[state[3][c]];

        for (int i = 0; i < 4; ++i) {
            state[i][c] = tmp[i];
        }
    }
}

void addRoundKey(uint8_t state[4][Nb], uint8_t* key) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            state[i][j] = state[i][j] ^ key[i + 4 * j];
        }
    }
}


void get_rcon(uint8_t* a, int n) {
    uint8_t c = 1;
    for (int i = 0; i < n - 1; i++) {
        c = xtime(c);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}

void keyExpansion(const uint8_t key[], uint8_t w[]) {
    uint8_t temp[4];
    uint8_t rcon[4];

    int i = 0;
    while (i < 4 * Nk) {
        w[i] = key[i];
        i++;
    }

    i = 4 * Nk;
    while (i < 4 * Nb * (Nr + 1)) {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % Nk == 0) {
            rotWord(temp);
            subWord(temp);
            get_rcon(rcon, i / (Nk * 4));
            xorWords(temp, rcon, temp);
        }
        else if (Nk > 6 && i / 4 % Nk == 4) {
            subWord(temp);
        }

        w[i + 0] = w[i - 4 * Nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
        i += 4;
    }
}


void encryptBlock(const uint8_t in[], uint8_t out[], uint8_t* roundKeys) {
    uint8_t state[4][Nb];

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    addRoundKey(state, roundKeys);

    for (int round = 1; round <= Nr - 1; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys + round * 4 * Nb);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }
}

void decryptBlock(const uint8_t in[], uint8_t out[], uint8_t* roundKeys) {
    uint8_t state[4][Nb];

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    addRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (int round = Nr - 1; round >= 1; round--) {
        invSubBytes(state);
        invShiftRows(state);
        addRoundKey(state, roundKeys + round * 4 * Nb);
        invMixColumns(state);
    }

    invSubBytes(state);
    invShiftRows(state);
    addRoundKey(state, roundKeys);

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }
}


void addPKCS7Padding(const std::vector<uint8_t>& data, std::vector<uint8_t>& padded_data) {
    int pad_sz = blockBytesSz - (data.size() % blockBytesSz);
    if (pad_sz == 0) {
        pad_sz = blockBytesSz;
    }
    padded_data.clear();
    padded_data.resize(data.size() + pad_sz);
    int i = 0;
    for (; i < data.size(); ++i) {
        padded_data[i] = data[i];
    }
    for (int j = 0; j < pad_sz; ++j) {
        padded_data[i + j] = pad_sz;
    }
}

void removePKCS7Padding(std::vector<uint8_t>& data) {
    if (data.empty() || data.size() % blockBytesSz != 0) {
        return;
    }
    uint8_t padValue = data.back();
    if (padValue == 0 || padValue > blockBytesSz) {
        return;
    }
    for (size_t i = data.size() - padValue; i < data.size(); ++i) {
        if (data[i] != padValue) {
            return;
        }
    }
    data.resize(data.size() - padValue);
}


//256 bit by default
void encrypt(const std::vector<uint8_t>& in, const std::vector<uint8_t>& key,
             const std::vector<uint8_t>& iv, std::vector<uint8_t>& out) {
    std::vector<uint8_t> padded_data;
    addPKCS7Padding(in, padded_data);
    if (!is_init) {
        is_init = true;
        generate_gf_tables();
    }
    size_t sz = padded_data.size();
    out.clear();
    out.resize(sz);
    uint8_t block[blockBytesSz];
    uint8_t* roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
    keyExpansion(key.data(), roundKeys);
    for (int i = 0; i < blockBytesSz; ++i) {
        block[i] = iv[i];
    }
    for (int i = 0; i < sz; i += blockBytesSz) {
        xorBlocks(block, padded_data.data() + i, block, blockBytesSz);
        encryptBlock(block, out.data() + i, roundKeys);
        for (int j = 0; j < blockBytesSz; ++j) {
            block[j] = out[i + j];
        }
    }

    delete[] roundKeys;
}


//256 bit by default
void decrypt(const std::vector<uint8_t>& in, const std::vector<uint8_t>& key,
             const std::vector<uint8_t>& iv, std::vector<uint8_t>& out) {
    size_t sz = in.size();
    out.clear();
    if (sz % blockBytesSz != 0) {
        return;
    }
    if (!is_init) {
        is_init = true;
        generate_gf_tables();
    }
    out.resize(sz);
    uint8_t block[blockBytesSz];
    uint8_t* roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
    keyExpansion(key.data(), roundKeys);
    for (int i = 0; i < blockBytesSz; ++i) {
        block[i] = iv[i];
    }
    for (int i = 0; i < sz; i += blockBytesSz) {
        decryptBlock(in.data() + i, out.data() + i, roundKeys);
        xorBlocks(block, out.data() + i, out.data() + i, blockBytesSz);
        for (int j = 0; j < blockBytesSz; ++j) {
            block[j] = in[i + j];
        }
    }

    removePKCS7Padding(out);

    delete[] roundKeys;
}


#undef Nb
#undef Nk
#undef Nr
#undef blockBytesSz

}


#endif // AES_H
