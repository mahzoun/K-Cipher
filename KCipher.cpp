//
// Created by sauron on 3/9/21.
//

#include "KCipher.h"
#include <crypto++/gf2n.h>
#include <crypto++/algebra.h>
#include <crypto++/cryptlib.h>


using namespace std;

template<size_t size>
bitset<size> &operator+(bitset<size> &A, bitset<size> &B) noexcept {
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
        int new_index = __kcipher_128_bitreordering[index][i];
        output[new_index] = input[i];
    }
    return output;
}

bitset<N> KCipher::SBox(bitset<N> input, bitset<N> rand[], int index) {
    bitset<N> output;
    for (int block = 0; block < N; block += M) {
        bitset<8> cur_block, cur_r0, cur_r1;
        long block_val, r0_val, r1_val;
        for (int i = block; i < block + M; i++) {
            cur_block[i] = input[i];
            cur_r0[i] = rand[2 * index][i];
            cur_r1[i] = rand[2 * index + 1][i];
        }
        block_val = cur_block.to_ulong();
        r0_val = cur_r0.to_ulong();
        r1_val = cur_r1.to_ulong();
        long t = sbox[block_val ^ r0_val] + r1_val;
        t = t % (1 << M);
        t = t << 2 | t >> M - 2; //this is weird
        cur_block = t;
        for (int i = block; i < block + M; i++) {
            output[i] = cur_block[i];
        }
    }
}

bitset<128> KCipher::EncCPA(bitset<128> input, bitset<128> K[4], bitset<128> rand[]) {
    for (int i = 0; i < 3; i++) {
        input = input + K[i];
        input = BitReordering(input, i);
        input = SBox(input, rand, i);
    }
    bitset<N> veil = BitReordering(K[2], 3);
    return input ^ veil;
}