//
// Created by sauron on 3/9/21.
//

#include "KCipher.h"
#include <crypto++/gf2n.h>
#include <crypto++/algebra.h>
#include <crypto++/cryptlib.h>


using namespace std;

template<size_t size>
bitset<size> operator+(bitset<size> &A, bitset<size> &B) noexcept {
    bitset<size> SUM;
    bool carry = 0;
    for (int i = 0; i < size; i++) {
        SUM[i] = A[i] ^ B[i] ^ carry;
        carry = (A[i] & B[i]) | (A[i] & carry) | (B[i] & carry);
    }
    return SUM;
}

bitset<N> KCipher::BitReordering(bitset<128> input, int index) {
    bitset<N> output;
    for (int i = 0; i < N; i++) {
        int new_index = reordering[index][i];
        output[new_index] = input[i];
    }
    return output;
}

bitset<N> KCipher::SBox(bitset<N> input, bitset<N> rand[], int index) {
    bitset<N> output;
    for (int block = 0; block < N; block += M) {
        bitset<M> cur_block, cur_r0, cur_r1;
        long block_val, r0_val, r1_val;
        for (int i = block; i < block + M; i++) {
            cur_block[i - block] = input[i];
            cur_r0[i - block] = rand[2 * index][i];
            cur_r1[i - block] = rand[2 * index + 1][i];
        }
        block_val = cur_block.to_ulong();
        r0_val = cur_r0.to_ulong();
        r1_val = cur_r1.to_ulong();
        long t = sbox[block_val ^ r0_val] + r1_val;
        t = t % (1 << M);
        //t = t << 2 | t >> M - 2; //this is weird
        cur_block = t;
        for (int i = block; i < block + M; i++) {
            output[i] = cur_block[i - block];
        }
    }
}

bitset<128> KCipher::EncCPA(bitset<128> input, bitset<128> key, bitset<128> rand[]) {
    cerr << input << endl;
    bitset<N> K[3];
    KeyExpansion(key, K);
    for (int i = 0; i < 3; i++) {
        input = input + K[i];
        input = BitReordering(input, i);
        input = SBox(input, rand, i);
    }
    bitset<N> veil = BitReordering(K[2], 3);
    return input ^ veil;
}

void KCipher::KeyExpansion(bitset<N> key, bitset<N> K[]) {
    bitset<N> C, U, rand[4];
    bitset<64> t[2];
    t[0] = __kcipher_range_65_128_const_1[0];
    t[1] = __kcipher_range_65_128_const_1[1];
    for (int j = 0; j < 128; j++)
        C[j] = j < 64 ? t[0][j] : t[1][j - 64];
    K[0] = key;
    U = C + key;
    U = BitReordering(U, 4);
    U = SBox(U, rand, -1);
    K[1] = BitReordering(U, 5);
    t[0] = __kcipher_range_65_128_const_2[0];
    t[1] = __kcipher_range_65_128_const_2[1];
    for (int j = 0; j < 128; j++)
        C[j] = j < 64 ? t[0][j] : t[1][j - 64];
    U = C + K[1];
    U = BitReordering(U, 6);
    U = SBox(U, rand, -1);
    K[2] = BitReordering(U, 7);
}
