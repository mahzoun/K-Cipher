#include "KCipher.h"
#include <iostream>
#include <fstream>
#include <random>
#include <cmath>
#include <ctime>

#define ROTL8(x, shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))
#define ROTR8(x, shift) ((uint8_t) ((x) >> (shift)) | ((x) << (8 - (shift))))
ofstream fout("ddt.out");
ofstream ffout("table.out");

KCipher kcipher;
bitset<N> key, r[6];
uint64_t key_table[1<<M][1<<M];
bitset<N> k3_candidates[1 << 16], r12_candidates[1 << 16];
uint16_t k3_bytes[2][16], r12_bytes[2][16];
bool gddt[1<<M][1<<M];
uint64_t key_val[14] = {0x27aef6116c4db0e6, 0x2779d02d3094d1df, 0xb8c0ad914767ba80, 0x6ca98308d45d1f79,
                        0xd75f78588ceaf21a, 0x3190bc4bfa457450, 0x92fd07e27f65d6c2, 0xd632a79fd631870c,
                        0x235548ef50bd1c1f, 0x002440be99b4d4ba, 0x1d038d1d35d9cd0f, 0xb1336f128aaebf73,
                        0x8028a087933b6f4a, 0x74fd2d5530ebb1f5};

template<size_t size>
bitset<size> operator+(bitset<size> &A, bitset<size> &B) noexcept {
    bitset<size> SUM;
    bool carry = 0;
    for (int i = 0; i < size; i++) {
        SUM[i] = A[i] ^ B[i] ^ carry;
        carry = (A[i] & B[i]) ^ (A[i] & carry) ^ (B[i] & carry);
    }
    return SUM;
}

template<size_t size>
bitset<size> operator-(bitset<size> &A, bitset<size> &B) noexcept {
    bitset<size> diff, B_c, one = 1, temp;
    for (int i = 0; i < size; i++)
        B_c[i] = 1;
    temp = B ^ B_c;
    diff = A + temp;
    diff = diff + one;
    return diff;
}

static std::random_device rd; // random device engine, usually based on /dev/random on UNIX-like systems
// initialize Mersennes' twister using rd to generate the seed
static std::mt19937 rng{rd()};

struct characteristic {
    uint32_t input_diff;
    uint32_t output_diff;
    uint32_t sbox;
    double probability;
};

void Random(bitset<N> &input) {
    static std::uniform_int_distribution<int> uid(0, 1); // random dice
    for (int i = 0; i < N; i++)
        input[i] = uid(rng);
}

void Init(){
    Random(key);
    for(int i = 0; i < 6; i++)
        Random(r[i]);
}

void DDT(uint8_t r1, bool gddt[256][256]) {
    uint8_t temp_sbox[256];
    uint8_t ddt[256][256];
    for (int i = 0; i < 256; i++)
        temp_sbox[i] = 0;

    for (int i = 0; i < 256; i++)
        for (int j = 0; j < 256; j++)
            ddt[i][j] = 0;

    for (int i = 0; i < 256; i++) {
        temp_sbox[i] = kcipher.sbox[i] + r1;
    }

    for (int x = 0; x < 256; x++) {
        for (int y = 0; y < 256; y++) {
            ddt[y][temp_sbox[x] ^ temp_sbox[x ^ y]]++;
        }
    }

    for (int i = 0; i < 256; i++)
        for (int j = 0; j < 256; j++)
            gddt[i][j] &= (ddt[i][j] > 0);
}

void Generate_GDDT() {
    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < 256; j++)
            gddt[i][j] = 1;
    }
    for (int R = 0; R < 256; R++) {
        DDT(R, gddt);
    }
}

uint8_t partial_dec(bitset<N> ct, uint8_t r1, uint8_t k, int position, int rounds) {
    bitset<M> temp;
    for (int i = 0; i < M; i++) {
        temp[i] = ct[128 - 8 * position + i];
    }
    uint8_t block_val = temp.to_ulong();
    block_val ^= k;
    block_val = ROTR8(block_val, 2);
    block_val -= r1;
    block_val = kcipher.sbox_inv[block_val];
    return block_val;
}

void differential_cryptanalysis(characteristic c) {
    bitset<N> p[2];
    bitset<N> ciphertext[2];
    Random(p[0]);
    p[1] = p[0];
    p[1][c.input_diff] = p[1][c.input_diff] ^ 1;
    for (int i = 0; i < 2; i++)
        ciphertext[i] = kcipher.EncCPA(p[i], key, r);
    uint8_t res[2];
    uint8_t expected_difference = 1 << (c.output_diff % 8);
    for (uint16_t k = 0; k < 256; k++) {
        for (uint16_t r1 = 0; r1 < 256; r1++) {
            res[0] = partial_dec(ciphertext[0], r1, k, c.sbox, 0);
            res[1] = partial_dec(ciphertext[1], r1, k, c.sbox, 0);
            if ((res[0] ^ res[1]) == expected_difference) {
                key_table[k][r1]++;
            }
        }
    }
}

void calculate_characteristic_probability(characteristic c) {
    // init keys for encryption
    bitset<N> K[3];
    bitset<N> p1, p2, c1, c2;
    int br = 0, br1 = 0, br2 = 0;
    unsigned int number_of_experiments = pow(2, 18);
    kcipher.KeyExpansion(key, K);
    bitset<N> expected_diff, exp1, exp2;
    for (int i = 0; i < N; i++) {
        expected_diff[i] = 0;
        exp1[i] = 0;
        exp2[i] = 0;
    }
    expected_diff.set(c.output_diff);
    for (int i = 0; i < number_of_experiments; i++) {
        Random(p1);
        p2 = p1;
        p2[c.input_diff] = p2[c.input_diff] ^ 1;
        c1 = p1 + K[0];
        c2 = p2 + K[0];

        c1 = kcipher.BitReordering(c1, 0);
        c2 = kcipher.BitReordering(c2, 0);

        c1 = kcipher.SBox(c1, r, 0);
        c2 = kcipher.SBox(c2, r, 0);

        //round 2
        c1 = c1 + K[1];
        c2 = c2 + K[1];

        c1 = kcipher.BitReordering(c1, 1);
        c2 = kcipher.BitReordering(c2, 1);

        c1 = kcipher.SBox(c1, r, 1);
        c2 = kcipher.SBox(c2, r, 1);
        c1 = c1 + K[2];
        c2 = c2 + K[2];
        c1 = kcipher.BitReordering(c1, 2);
        c2 = kcipher.BitReordering(c2, 2);
        if ((c1 ^ c2) == expected_diff) {
            br++;
        }
    }
    double proball = (double) br / number_of_experiments;
    proball = log2(proball);
    c.probability = proball;
    cout << "Characteristic: " << c.input_diff << " -> " << c.output_diff << " on sbox number: " << c.sbox << " holds with probability: 2^" << c.probability << endl;

}

void last_round_attack() {
    uint8_t c_arr_1[16][3] = {{62,  124, 1},
                              {36,  117, 2},
                              {33,  108, 3},
                              {117, 101, 4},
                              {14,  92,  5},
                              {45,  86,  6},
                              {102, 79,  7},
                              {126, 67,  8},
                              {106, 63,  9},
                              {90,  52,  10},
                              {34,  47,  11},
                              {98,  31,  12},
                              {28,  28,  13},
                              {8,   23,  14},
                              {118, 15,  15},
                              {41,  6,   16}};
    for (int t = 0; t < 16; t++) {
        for (int i = 0; i < 256; i++)
            for (int j = 0; j < 256; j++)
                key_table[i][j] = 0;
        characteristic c;
        c.input_diff = c_arr_1[t][0];
        c.output_diff = c_arr_1[t][1];
        c.sbox = c_arr_1[t][2];
        calculate_characteristic_probability(c);
        for (int i = 0; i < (1 << 16); i++) {
            differential_cryptanalysis(c);
        }
        int maxk = 0, maxr1 = 0;
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                if (key_table[i][j] > key_table[maxk][maxr1]) {
                    maxk = i;
                    maxr1 = j;
                }
            }
        }
        cout << c.input_diff << "\t" << c.output_diff << "\t" << c.probability << "\t" << c.sbox << endl;
        int tmp_index = 0;
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                if (key_table[i][j] == key_table[maxk][maxr1]) {
                    cout << hex << i << "\t" << j << "\t" << key_table[i][j] << endl;
                    int index = t < 8 ? t + 8 : t - 8;
                    k3_bytes[tmp_index][index] = i;
                    r12_bytes[tmp_index][index] = j;
                    tmp_index++;
                    if (tmp_index > 1) {
                        cout << "More than two candidates found, there must be a problem.\n";
                        return;
                    }
                }
            }
        }
        cout << "\n________________________\n";
    }
    for (uint32_t I = 0; I < (1 << 16); I++) {
        uint32_t temp = I;
        for (int idx = 0; idx < 16; idx++) {
            bitset<8> cur_key = k3_bytes[temp % 2][15 - idx];
            bitset<8> cur_rand = r12_bytes[temp % 2][15 - idx];
            temp/=2;
            for (int i = 0; i < 8; i++) {
                k3_candidates[I][idx * 8 + i] = cur_key[i];
                r12_candidates[I][idx * 8 + i] = cur_rand[i];
            }
        }
    }
}

using namespace std;

int main(int argc, char **argv) {
    ios_base::sync_with_stdio(false);
    Init();
    last_round_attack();
    return 0;
}
