#include "KCipher.h"
#include <iostream>
#include <fstream>
#include <random>
#include <cmath>
#include <ctime>

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))
#define ROTR8(x,shift) ((uint8_t) ((x) >> (shift)) | ((x) << (8 - (shift))))

ofstream fout("ddt.out");

KCipher kcipher;
int Count[256];

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

void DDT(uint8_t r1, bool gddt[256][256]) {
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

    for (int i = 0; i < 256; i++)
        for (int j = 0; j < 256; j++)
            gddt[i][j] &= (ddt[i][j] > 0);
}

uint8_t partial_dec(bitset<N> ct, uint8_t r1, uint8_t k, int position){
    bitset<M> temp;
    for(int i = 0; i < M; i++){
        temp[i] = ct[128 - 8 * position + i];
    }
    uint8_t block_val = temp.to_ulong();
    block_val ^= k;
    block_val = ROTR8(block_val, 2);
    block_val -= r1;
    block_val = kcipher.sbox_inv[block_val];
    return block_val;
}

uint8_t key_table[256][256];
void differential_cryptanalysis() {
    bitset<N> p[2], r[6];
    Random(p[0]);
    p[1] = p[0];
    p[1][N - 1] = p[1][N - 1] ^ 1;
//    p2[107] = p2[107] ^ 1;
//    p2[50] = p2[50] ^ 1;
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
    uint8_t expected_difference = 1;
    for(uint8_t k = 0; k < 256; k++) {
        for (uint8_t r1 = 0; r1 < 256; r1++) {
            res[0] = partial_dec(ciphertext[0], r1, k, 1);
            res[1] = partial_dec(ciphertext[1], r1, k, 1);
            if (res[0] ^ res[1] == expected_difference)
                key_table[k][r1]++;
        }
    }
}


void diff_cryptanalysis_ChProbability()
{
    uint32_t counterDiffProb;
    uint32_t total;

    total = 1024*128;
    counterDiffProb = 0;

    std:cout << "total = " << total<<endl;

    uint64_t key_val[14] = { 0x27aef6116c4db0e6, 0x2779d02d3094d1df, 0xb8c0ad914767ba80, 0x6ca98308d45d1f79,
                             0xd75f78588ceaf21a, 0x3190bc4bfa457450, 0x92fd07e27f65d6c2, 0xd632a79fd631870c,
                             0x235548ef50bd1c1f, 0x002440be99b4d4ba, 0x1d038d1d35d9cd0f, 0xb1336f128aaebf73,
                             0x8028a087933b6f4a, 0x74fd2d5530ebb1f5 };

    //I try to generate the key at random to get a better intuition on the probability.
    //for (int i = 0;i < 7;i++)
    //{
    //	bitset<N> temp_k;
    //	Random(temp_k);
    //	//cout << temp_k << endl;

    //	bitset<64> tmp1, tmp2;

    //	for (uint8_t j = 0;j < 64;j++)
    //	{
    //		tmp1[j] = temp_k[j];

    //	}

    //	//	//cout << tmp1 << endl;

    //	for (uint8_t j = 64;j < 128;j++)
    //	{
    //		tmp2[j - 64] = temp_k[j];

    //	}

    //	//	//cout << tmp2 << endl;

    //	key_val[2 * i] = tmp1.to_ullong();
    //	key_val[2 * i + 1] = tmp2.to_ullong();
    //}

    //cout << key_val[0] << endl;


    bitset<64> t[2];
    bitset<N> key;
    t[0] = key_val[0];
    t[1] = key_val[1];
    for (int i = 0; i < 128; i++)
        key[i] = i < 64 ? t[0][i] : t[1][i - 64];

    bitset<N> K[3];
    kcipher.KeyExpansion(key, K);

    bitset<N> rand[6];
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

    for (int T = 0;T < total;T++)
    {
        //std::cout << "iteration: " << T << "  ";
        bitset<N> p1, p2;//, r[6];
        Random(p1);
        p2 = p1;

        uint8_t index1 = N - 56;//N - 1;//N-56;
        p2[index1] = p2[index1] ^ 1;


        bitset<N> ciphertext[2];
        //ciphertext[0] = p1 + K[0];
        //ciphertext[1] = p2 + K[0];

        ciphertext[0] = p1;
        ciphertext[1] = p2;
        /*	cout << rand[0] << endl;
            cout << rand[1] << endl;
            cout << rand[2] << endl;
            cout << rand[3] << endl;
            cout << rand[4] << endl;
            cout << rand[5] << endl;*/

        int round = 0;
        //for (int i = 0; i < 2; i++) {

        /*	ciphertext[0] = kcipher.BitReordering(ciphertext[0], 10);
            ciphertext[1] = kcipher.BitReordering(ciphertext[1], 10);

            cout << (ciphertext[0] ^ ciphertext[1]) << endl;*/

        //ciphertext[0] = kcipher.SBox(ciphertext[0], rand, round-1);
        //ciphertext[1] = kcipher.SBox(ciphertext[1], rand, round-1);
        round = 0;
        //for (round = 0;round <= 1;round++)
        {
            ciphertext[0] = ciphertext[0] + K[round];
            ciphertext[1] = ciphertext[1] + K[round];

            ciphertext[0] = kcipher.BitReordering(ciphertext[0], round);
            ciphertext[1] = kcipher.BitReordering(ciphertext[1], round);
            // cout << (ciphertext[0] ^ ciphertext[1]) << endl;

            ciphertext[0] = kcipher.SBox(ciphertext[0], rand, round);
            ciphertext[1] = kcipher.SBox(ciphertext[1], rand, round);
            //if((round==0))
            // cout << (ciphertext[0] ^ ciphertext[1]) << endl;
        }
        //ciphertext[0] = ciphertext[0] + K[1];
        //ciphertext[1] = ciphertext[1] + K[1];
        // cout << (ciphertext[0] ^ ciphertext[1]) << endl;

        //ciphertext[0] = kcipher.BitReordering(ciphertext[0], 1);
        //ciphertext[1] = kcipher.BitReordering(ciphertext[1], 1);
        //cout << (ciphertext[0] ^ ciphertext[1]) << endl;

        //ciphertext[0] = kcipher.SBox(ciphertext[0], rand, 1);
        // ciphertext[1] = kcipher.SBox(ciphertext[1], rand, 1);

        //ciphertext[0] = ciphertext[0] + K[2];
        //ciphertext[1] = ciphertext[1] + K[2];

        //ciphertext[0] = kcipher.BitReordering(ciphertext[0], 0);
        //ciphertext[1] = kcipher.BitReordering(ciphertext[1], 0);

        // cout << (ciphertext[0] ^ ciphertext[1]) << endl;
        // cout << (ciphertext[0] ^ ciphertext[1]) << endl;
        //cout << "-------------------------------------------------" << endl;
        //ciphertext[i] = ciphertext[i] + K[2];
        //}

        int counter = 0;
        for (int i = N - 8; i >= 0; i -= 8) {
            bitset<8> cur_box;
            for (int j = 0; j < 8; j++)
                cur_box[j] = ciphertext[0][i + j] ^ ciphertext[1][i + j];
            if (cur_box.to_ulong() > 0)
                counter++;

            //cout << hex << cur_box.to_ulong() << "  ";
        }
        //cout << " | " << counter << " -> ";

        bool flag=true;

        for (int i = 0;i < N;i++)
        {
            if (i == (N - 1))
            {
                if (ciphertext[0][i] == ciphertext[1][i])
                    flag = false;
            }
            else
            {
                if (ciphertext[0][i] != ciphertext[1][i])
                    flag = false;
            }

        }


        /*
            for (int i = 0;i < N;i++)
            {
                if ((i > (N - 17))||(i<(N-24)))
                {
                    if (ciphertext[0][i] != ciphertext[1][i])
                        flag = false;
                }

            }*/

        if (flag == true)
        {
            //cout << ciphertext[0] << endl << ciphertext[1] << endl << (ciphertext[0] ^ ciphertext[1]) << endl<<endl;

            round = 1;
            ciphertext[0] = ciphertext[0] + K[round];
            ciphertext[1] = ciphertext[1] + K[round];

            ciphertext[0] = kcipher.BitReordering(ciphertext[0], round);
            ciphertext[1] = kcipher.BitReordering(ciphertext[1], round);

            ciphertext[0] = kcipher.SBox(ciphertext[0], rand, round);
            ciphertext[1] = kcipher.SBox(ciphertext[1], rand, round);

            //cout << (ciphertext[0] ^ ciphertext[1]) << endl <<endl;
            //cout << counterDiffProb<<endl;


            if ((ciphertext[0] ^ ciphertext[1]).count() == 1)
            {
                cout << (ciphertext[0] ^ ciphertext[1]) << endl << endl;

                bool flag1 = true;

                for (int i = 0;i < N;i++)
                {
                    if (i == (N - 22))
                    {
                        if (ciphertext[0][i] == ciphertext[1][i])
                            flag1 = false;
                    }
                    else
                    {
                        if (ciphertext[0][i] != ciphertext[1][i])
                            flag1 = false;
                    }

                }

                if (flag1 == true)
                    counterDiffProb++;
            }

        }


        //std::cout << counterDiffProb << endl;
    }

    std::cout << dec << counterDiffProb << "/" << total << endl;
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
//    for (int i = 0; i < 1; i++)
//        differential_cryptanalysis();
    diff_cryptanalysis_ChProbability();
//    int maxk = 0, maxr1 = 0;
//    for (int i = 0; i < 256; i++){
//        for (int j = 0; j < 256; j++) {
//            if (key_table[i][j] > key_table[maxk][maxr1]) {
//                maxk = i;
//                maxr1 = j;
//            }
//        }
//    }
//    cout << maxk << "\t" << maxr1 << endl;
//    for (int i = 0; i < 256; i++){
//        for (int j = 0; j < 256; j++) {
//            cout << (int)key_table[i][j] << "\t";
//        }
//        cout << endl;
//    }
    return 0;
}



