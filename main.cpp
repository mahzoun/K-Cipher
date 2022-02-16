#include "KCipher.h"
#include <iostream>
#include <random>
#include <chrono>
#include <cmath>

/*
 * These variables are global for the sake of efficiency of the code.
 */
KCipher kcipher;
bitset<N> r[6];
bitset<K> key;
uint64_t key_table[1 << M][1 << M];

struct characteristic {
    uint32_t input_diff;
    uint32_t output_diff;
    uint32_t sbox;
    double probability;
};

/*
 * random device engine, usually based on /dev/random on UNIX-like systems
 * initialize Mersennes' twister using rd to generate the seed
*/
static std::random_device rd;
static std::mt19937 rng{rd()};
template<size_t size>
void Random(bitset<size> &input) {
    static std::uniform_int_distribution<int> uid(0, 1); // random dice
    for (int i = 0; i < size; i++)
        input[i] = uid(rng);
}

void Init() {
    /*
     * This function generates new key and randomizers for each run. To have fixed key and randomizers, set them here.
     */
    Random(key);
    for (int i = 0; i < 6; i++) {
        Random(r[i]);
    }

}

inline uint8_t partial_dec(bitset<N> ct, uint8_t r1, uint8_t k, int position, int rounds) {
    bitset<M> temp;
    for (int i = 0; i < M; i++) {
        temp[i] = ct[N - 8 * position + i];
    }
    uint8_t block_val = temp.to_ulong();
    block_val ^= k;
    block_val = ROTR8(block_val, 2);
    block_val -= r1;
    block_val = kcipher.sbox_inv[block_val];
    return block_val;
}

inline void differential_cryptanalysis_key_recovery(characteristic c) {
    /*
     * key recovery function recovers the last round key and randomizer
     */
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

void differential_cryptanalysis_distinguisher(characteristic c) {
    /*
     * The distinguisher function computes the probability of the characteristic c
     */
    bitset<N> K[3];
    bitset<N> p1, p2, c1, c2;
    int br = 0;
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
    cout << "Characteristic: " << c.input_diff << " -> " << c.output_diff << " on sbox number: " << c.sbox
         << " holds with probability: 2^" << c.probability << endl;

}

void last_round_attack() {
    uint8_t c_arr_1[5][3] = {{22,  16, 1},
                             {5,  16, 1},
                             {15,  13, 2},
                             {19, 2, 3},
                             {18,  5,  3}};
    uint8_t c_arr_2[16][3] = {{62,  124, 1},
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
    for (int t = 0; t < 5; t++) {
        for (int i = 0; i < 256; i++)
            for (int j = 0; j < 256; j++)
                key_table[i][j] = 0;
        characteristic c;
        c.input_diff = c_arr_1[t][0];
        c.output_diff = c_arr_1[t][1];
        c.sbox = c_arr_1[t][2];
        /*
         * uncomment the following function call to run the distinguisher attack.
         */
        differential_cryptanalysis_distinguisher(c);
        for (int i = 0; i < (1 << 16); i++) {
            differential_cryptanalysis_key_recovery(c);
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
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                if (key_table[i][j] == key_table[maxk][maxr1]) {
                    cout << hex << i << "\t" << j << "\t" << key_table[i][j] << endl;
                }
            }
        }
        cout << "\n________________________\n";
    }
}

using namespace std;
using chrono::high_resolution_clock;
using chrono::duration_cast;
using chrono::duration;
using chrono::milliseconds;

int main(int argc, char **argv) {
    ios_base::sync_with_stdio(false);
    string key_string = "001011001011111011010001111001000101100101111010100101011100111000100101010111000001011100000011";
    bitset<K> temp(key_string);     
    key = temp;
    bitset<N> rand2[6];

    rand2[0] = 0x4d82b5;
    rand2[1] = 0xdb8760;
    rand2[2] = 0x02011e;
    rand2[3] = 0x71fc2a;
    rand2[4] = 0x000072;
    rand2[5] = 0xa92a9a;
    for (int i = 0; i < 6; i++)
        r[i] = rand2[i];
    auto t1 = high_resolution_clock::now();
    last_round_attack();
    auto t2 = high_resolution_clock::now();
    duration<double, std::milli> ms_double = t2 - t1;
    cout << "The attack finished in(ms):" << ms_double.count() << endl;
    return 0;
}
