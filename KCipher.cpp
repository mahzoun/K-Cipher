//
// Created by sauron on 3/9/21.
//

#include <bit>
#include <bitset>
#include <cstdint>
#include <iostream>
#include "KCipher.h"

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))
#define ROTR8(x,shift) ((uint8_t) ((x) >> (shift)) | ((x) << (8 - (shift))))
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

template<size_t size>
bitset<size> operator-(bitset<size> &A, bitset<size> &B) noexcept {
    bitset<size> diff, B_c, one = 1;
    for (int i = 0; i < size; i++)
        B_c[i] = 1;
    B = B ^ B_c;
    diff = A + B;
    diff = diff + one;
    return diff;
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
        uint8_t t = sbox[block_val ^ r0_val] + r1_val;
        t = ROTL8(t, 2);
        cur_block = t;
        for (int i = block; i < block + M; i++) {
            output[i] = cur_block[i - block];
        }
    }
    return output;
}

bitset<N> KCipher::Inv_SBox(bitset<N> input, bitset<N> rand[], int index) {
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
        uint8_t t = block_val;
//        cerr << bitset<8>(t) << endl;
        t = ROTR8(t, 2);
//        cerr << bitset<8>(t) << endl;
        t -= r1_val;
        t = sbox_inv[t] ^ r0_val;
        cur_block = t;
        for (int i = block; i < block + M; i++) {
            output[i] = cur_block[i - block];
        }
    }
    return output;
}

bitset<128> KCipher::EncCPA(bitset<128> input, bitset<128> key, bitset<128> rand[]) {
//    cerr << input << endl;
    bitset<N> K[3];
    KeyExpansion(key, K);
//    bitset<N> temp = BitReordering(K[2], 3);
//    for(int i = N-1 ; i >= 0; i--){
//        cout << temp[i];
//        if(i % 8 == 0)
//            cout <<"\t";
//    }
//    cout << endl;
    for (int i = 0; i < 3; i++) {
        input = input + K[i];
//        cerr << input << endl;
        input = BitReordering(input, i);
//        cerr << i << "\t" << input << endl;
        input = SBox(input, rand, i);
//        cerr << i << "\t" << input << endl;
    }
    bitset<N> veil = BitReordering(K[2], 3);
//    cerr << (input ^ veil) << endl;
    return input ^ veil;
}

bitset<128> KCipher::DecCPA(bitset<128> input, bitset<128> key, bitset<128> rand[]) {
//    cerr << "\n___________________\n";
//    cerr << input << endl;
    bitset<N> K[3];
    KeyExpansion(key, K);
    bitset<N> veil = BitReordering(K[2], 3);
    input = input ^ veil;
//    cerr << input << endl;
    for (int i = 0; i < 3; i++) {
//        cerr << i << "\t" << input << endl;
        input = Inv_SBox(input, rand, 2 - i);
//        cerr << i << "\t" << input << endl;
        input = BitReordering(input, 12 - i);
//        cerr << input << endl;
        input = input - K[2 - i];
//        cerr << input << endl;
    }
//    cerr << "\n___________________\n";
    return input;
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
