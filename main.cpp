#include "KCipher.h"
#include <iostream>
#include <fstream>
#include <random>
#include <cmath>
#include <ctime>

ofstream fout("ddt.out");

KCipher kcipher;

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

void Random(bitset<N> &input) {
    for (int i = 0; i < N; i++)
        input[i] = rand() % 2;
}

uint8_t DDT(uint8_t r1, bool gddt[256][256]) {
    KCipher kcipher;
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

    for(int i = 0; i < 256; i++)
        for(int j = 0; j < 256; j++)
            gddt[i][j] &= (ddt[i][j]>0);
}

void differential_cryptanalysis() {
    bitset<N> p1, p2, r[6];
    Random(p1);
    p2 = p1;
    p2[94] = p2[94] ^ 1;
    p2[87] = p2[87] ^ 1;
//    bool gddt[256][256];
//    for(int i = 0; i < 256;i++) {
//        for (int j = 0; j < 256; j++)
//            gddt[i][j] = 1;
//    }
//    for(int R = 0; R < 256; R++){
//        DDT(R, gddt);
//    }

//    for(int i = 0 ; i < 256; i++)
//        for(int j = 0 ; j < 256; j++)
//            if(gddt[i][j])
//                cout << i << "\t" << j << endl;

//    for(int i = 0; i < 256; i++){
//        for(int j = 0; j < 256; j++){
//            if(gddt[i][j])
//                fout << i << "\t" << j << endl;
//        }
//    }


    uint64_t key_val[14] = {0x27aef6116c4db0e6, 0x2779d02d3094d1df, 0xb8c0ad914767ba80, 0x6ca98308d45d1f79,
                            0xd75f78588ceaf21a, 0x3190bc4bfa457450, 0x92fd07e27f65d6c2, 0xd632a79fd631870c,
                            0x235548ef50bd1c1f, 0x002440be99b4d4ba, 0x1d038d1d35d9cd0f, 0xb1336f128aaebf73,
                            0x8028a087933b6f4a, 0x74fd2d5530ebb1f5};
    bitset<64> t[2];
    bitset<N> key;
    t[0] = key_val[0];
    t[1] = key_val[1];
    for (int i = 0; i < 128; i++)
        key[i] = i < 64 ? t[0][i] : t[1][i - 64];

    bitset<N> K[3];
    kcipher.KeyExpansion(key, K);
    bitset<N> ciphertext[2];
    ciphertext[0] = p1 + K[0];
    ciphertext[1] = p2 + K[0];
    for (int i = 0; i < 2; i++) {
        ciphertext[i] = kcipher.BitReordering(ciphertext[i], 1);
    }
    int counter = 0;
    for (int i = N - 1; i >= 0; i-=8) {
        bitset<8> cur_box;
        for(int j = 0; j < 8; j++)
            cur_box[j] = ciphertext[0][i + j] ^ ciphertext[1][i + j];
        if(cur_box.to_ulong() > 0)
            counter++;
        cout << hex << cur_box.to_ulong() << "\t";
    }
    cout << counter << endl;

//    for (int i = 0; i < 2; i++) {
//        ciphertext[i] = kcipher.SBox(ciphertext[i], r, 0);
//    }
//    for (int i = N - 1; i >= 0; i--) {
//        cout << (ciphertext[0][i] ^ ciphertext[1][i]);
//        if ((i) % 8 == 0)
//            cout << "\t";
//    }
//    cout << endl << endl;
    //cout << (ciphertext[0] ^ ciphertext[1]) << endl << endl;
}


using namespace std;

int main(int argc, char **argv) {
    srand(time(0));
    for (int i = 0; i < 100; i++)
        differential_cryptanalysis();
//    uint64_t plain=text_val[2] = {0x2b58bffc83cc6c39, 0x24f22580b2107da7};
//    uint64_t key_val[14] = {0x27aef6116c4db0e6, 0x2779d02d3094d1df, 0xb8c0ad914767ba80, 0x6ca98308d45d1f79,
//                            0xd75f78588ceaf21a, 0x3190bc4bfa457450, 0x92fd07e27f65d6c2, 0xd632a79fd631870c,
//                            0x235548ef50bd1c1f, 0x002440be99b4d4ba, 0x1d038d1d35d9cd0f, 0xb1336f128aaebf73,
//                            0x8028a087933b6f4a, 0x74fd2d5530ebb1f5};
//    uint64_t cipher_val[2] = {0xa3f53f715d01e6eb, 0xa8c1904ee7567837};
//    bitset<64> t[2];
//    bitset<N> input, key, rand[6], output, dec;
//    t[0] = plaintext_val[0];
//    t[1] = plaintext_val[1];
//    for (int i = 0; i < 128; i++)
//        input[i] = i < 64 ? t[0][i] : t[1][i - 64];
//    t[0] = key_val[0];
//    t[1] = key_val[1];
//    for (int i = 0; i < 128; i++)
//        key[i] = i < 64 ? t[0][i] : t[1][i - 64];
//    for (int i = 0; i < 6; i++) {
//        t[0] = key_val[2 * i + 2];
//        t[1] = key_val[2 * i + 3];
//        for (int j = 0; j < 128; j++)
//            rand[i][j] = j < 64 ? t[0][j] : t[1][j - 64];
//    }
//
//    bitset<N> sbox_output = kcipher.SBox(input, rand, 0);
//    output = kcipher.EncCPA(input, key, rand);
//    dec = kcipher.DecCPA(output, key, rand);
//    cout << input << endl << output << endl << dec << endl;
    return 0;
}



