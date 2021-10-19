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
uint64_t key_table[256][256];
bool gddt[256][256];
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
static std::mt19937 rng{ rd() };

struct characteristic{
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

void Generate_GDDT(){
    for(int i = 0; i < 256;i++) {
        for (int j = 0; j < 256; j++)
            gddt[i][j] = 1;
    }
    for(int R = 0; R < 256; R++){
        DDT(R, gddt);
    }
}

uint8_t partial_dec(bitset<N> ct, uint8_t r1, uint8_t k, int position) {
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
    bitset<N> p[2], r[6];
    Random(p[0]);
    p[1] = p[0];
    p[1][c.input_diff] = p[1][c.output_diff] ^ 1;
    bitset<64> t[2];
    bitset<N> key;
    t[0] = key_val[0];
    t[1] = key_val[1];
    for (int i = 0; i < 128; i++)
        key[i] = i < 64 ? t[0][i] : t[1][i - 64];
    for (int i = 0; i < 6; i++) {
        t[0] = key_val[2 * i + 2];
        t[1] = key_val[2 * i + 3];
        for (int j = 0; j < 128; j++)
            r[i][j] = j < 64 ? t[0][j] : t[1][j - 64];
    }

    bitset<N> ciphertext[2];
    for (int i = 0; i < 2; i++)
        ciphertext[i] = kcipher.EncCPA(p[i], key, r);
    uint8_t res[2];
    uint8_t expected_difference = 4;
//    uint16_t r1 = 0xb1;
//    uint16_t k = 0x3b;
    for (uint16_t k = 0; k < 256; k++) {
        for (uint16_t r1 = 0; r1 < 256; r1++) {
            res[0] = partial_dec(ciphertext[0], r1, k, c.sbox);
            res[1] = partial_dec(ciphertext[1], r1, k, c.sbox);
            if ((res[0] ^ res[1]) == expected_difference) {
                key_table[k][r1]++;
            }
        }
    }
}

void calculate_characteristic_probability(characteristic c) {
    // init keys for encryption
    bitset<64> t[2];
    bitset<N> key, rand[6];
    t[0] = key_val[0];
    t[1] = key_val[1];
    for (int i = 0; i < 128; i++)
        key[i] = i < 64 ? t[0][i] : t[1][i - 64];
    for (int i = 0; i < 6; i++) {
        t[0] = key_val[2 * i + 2];
        t[1] = key_val[2 * i + 3];
        for (int j = 0; j < 128; j++)
            rand[i][j] = j < 64 ? t[0][j] : t[1][j - 64];
    }
    bitset<N> K[3];
    bitset<N> p1, p2, c1, c2;
    int br = 0, br1 = 0, br2 = 0;
    unsigned int number_of_experiments = pow(2, 18);

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

        c1 = kcipher.SBox(c1, rand, 0);
        c2 = kcipher.SBox(c2, rand, 0);

        //round 2
        c1 = c1 + K[1];
        c2 = c2 + K[1];

        c1 = kcipher.BitReordering(c1, 1);
        c2 = kcipher.BitReordering(c2, 1);

        c1 = kcipher.SBox(c1, rand, 1);
        c2 = kcipher.SBox(c2, rand, 1);
        c1 = c1 + K[2];
        c2 = c2 + K[2];
        c1 = kcipher.BitReordering(c1, 2);
        c2 = kcipher.BitReordering(c2, 2);
        if ((c1 ^ c2) == expected_diff) {
            br++;
        }
    }
    double prob1 = (double) br1 / number_of_experiments;
    prob1 = log2(prob1);
    double prob2 = (double) br2 / number_of_experiments;
    prob2 = log2(prob2);
    double proball = (double) br / number_of_experiments;
    proball = log2(proball);
    c.probability = proball;
//    cout << "Br after round 1 = " << br1<<" , holds with prob "<<prob1 << endl;
//    cout << "Br after round 2 " << br2 << " , holds with prob " << prob2 << endl;
    cout << "Characteristic holds with probability 2^" << c.probability << endl;
//    cout << "prob of scond holding when first did: " << log2((double)br / br1) << endl;

}

using namespace std;

void test_() {
    uint8_t block_val, k, r1;
    uint64_t counter = 0;
    for(int i = 0; i < 256; i++){
        for(int j = 0; j < 256; j++){
            for(int ii = 0; ii < 256; ii++){
                counter++;
                block_val = i;
                k = j;
                r1 = ii;
                uint8_t temp = block_val, temp2 = block_val;
                uint8_t k_temp = k + 2;
                uint8_t r1_temp = r1 + 128;
                temp2 ^= k;
                temp2 = ROTR8(temp2, 2);
                temp2 -= r1;
                temp2 = kcipher.sbox_inv[temp2];
                temp ^= k_temp;
                temp = ROTR8(temp, 2);
                temp -= r1_temp;
                temp = kcipher.sbox_inv[temp];
                if(k % 4 ==0 & temp != temp2)
                    cout << counter  << "\t" << (int)block_val << "\t" << (int)k << "\t" <<  (int)r1 << "\t" << (int)r1_temp << "\t" << (int)k << "\t" << (int)k_temp << "\t" << (int)temp2 << "\t" << (int)temp <<endl;
            }
        }
    }

}
int main(int argc, char **argv) {
    ios_base::sync_with_stdio(false);
    characteristic c;
    c.input_diff = 8;
    c.output_diff = 23;
    c.sbox = 8;
    //calculate_characteristic_probability(c);
    for (int i = 0; i < (1<<16); i++) {
        if (i % 4096  == 0)
            cerr << i << endl;
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
    cout << maxk << "\t" << maxr1 << endl;
    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < 256; j++) {
            if (key_table[i][j] == key_table[maxk][maxr1])
               cout << i << "\t" << j << "\t" << key_table[i][j] << endl;
            ffout << (int) key_table[i][j] << "\t";
        }
        ffout << endl;
    }
    return 0;
}
