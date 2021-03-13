#include "KCipher.h"
#include <iostream>
#include <cmath>


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
    bitset<size> diff, B_c, one = 1, temp;
    for (int i = 0; i < size; i++)
        B_c[i] = 1;
    temp = B ^ B_c;
    diff = A + temp;
    diff = diff + one;
    return diff;
}

using namespace std;

int main(int argc, char **argv) {
    KCipher kcipher;
    uint64_t plaintext_val[2] = {0x2b58bffc83cc6c39, 0x24f22580b2107da7};
    uint64_t key_val[14] = {0x27aef6116c4db0e6, 0x2779d02d3094d1df, 0xb8c0ad914767ba80, 0x6ca98308d45d1f79,
                            0xd75f78588ceaf21a, 0x3190bc4bfa457450, 0x92fd07e27f65d6c2, 0xd632a79fd631870c,
                            0x235548ef50bd1c1f, 0x002440be99b4d4ba, 0x1d038d1d35d9cd0f, 0xb1336f128aaebf73,
                            0x8028a087933b6f4a, 0x74fd2d5530ebb1f5};
    uint64_t cipher_val[2] = {0xa3f53f715d01e6eb, 0xa8c1904ee7567837};
    bitset<64> t[2];
    bitset<N> input, key, rand[6], output, dec;
    t[0] = plaintext_val[0];
    t[1] = plaintext_val[1];
    for (int i = 0; i < 128; i++)
        input[i] = i < 64 ? t[0][i] : t[1][i - 64];
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

//    bitset<N> sbox_output = kcipher.SBox(input, rand, 0);
    output = kcipher.EncCPA(input, key, rand);
    dec = kcipher.DecCPA(output, key, rand);
    cout << input << endl << output << endl << dec << endl;
    return 0;
}

