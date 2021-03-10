//
// Created by sauron on 3/9/21.
//

#include "KCipher.h"
#include <crypto++/gf2n.h>
#include <crypto++/algebra.h>
#include <crypto++/cryptlib.h>


using namespace std;

template <size_t size>
bitset<size>& operator+(bitset<size>& A, bitset<size>& B) noexcept {
    bitset<size> SUM;
    bool carry = 0;
    for(int i = 0; i < size; i++) {
        SUM[i] = A[i] ^ B[i] ^ carry;
        carry = (A[i] & B[i]) | (A[i] & carry) | (B[i] & carry);
    }
    return SUM;
}

bitset<N> KCipher::BitReordering(bitset<128> input, int index) {
    bitset<N> output;
    for(int i = 0; i < N; i++) {
        int new_index = __kcipher_128_bitreordering[index][i];
        output[new_index] = input[i];
    }
    return output;
}

bitset<128> KCipher::SBox(bitset<128> input, bitset<128> rand, int index) {
    return input;
}

bitset<128> KCipher::EncCPA(bitset<128>input , bitset<128> K[4], bitset<128> rand) {
    for(int i = 0; i < 3; i++) {
        input = input + K[i];
        input = BitReordering(input, i);
        input = SBox(input, rand, i);
    }
    bitset<N> veil = BitReordering(K[2], 3);
    return input ^ veil;
}