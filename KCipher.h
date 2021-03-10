//
// Created by sauron on 3/9/21.
//

#ifndef K_CIPHER_KCIPHER_H
#define K_CIPHER_KCIPHER_H

#include <functional>
#include <iostream>
#include <cstdint>
#include <random>
#include <bitset>
#include <chrono>

#define N 128   //State size
#define M 8    //Block size used in SBox inversion
using namespace std;

class KCipher {
public:
    uint64_t __kcipher_range_65_128_const_0[2] = {0x5f63c0ec346ddc37, 0xf98c63bbbbefa08e};
    uint64_t __kcipher_range_65_128_const_1[2] = {0x44aa7cb19f6d53a0, 0x43daa42d7323101a};
    uint64_t __kcipher_range_65_128_const_2[2] = {0xb3b27e401ae99fd0, 0x84177319f57a5e1b};

    int __kcipher_128_bitreordering[4][128] = { {79, 121, 89, 83, 99, 31, 64, 21, 40, 62, 7, 33, 9, 114, 111, 54, 4, 68,
                                              73, 90, 103, 110, 37, 115, 41, 52, 84, 124, 8, 16, 28, 63, 10, 96, 93, 32,
                                              50, 2, 43, 109, 86, 125, 60, 119, 29, 66, 74, 18, 53, 20, 97, 42, 81, 12,
                                              1, 106, 30, 70, 35, 59, 118, 78, 120, 95, 108, 6, 47, 58, 116, 23, 11, 82,
                                              127, 65, 26, 36, 48, 91, 72, 100, 46, 104, 56, 80, 0, 27, 76, 51, 67, 22,
                                              117, 38, 126, 92, 98, 13, 17, 101, 88, 123, 57, 45, 15, 75, 107, 5, 69,
                                              49, 113, 39, 85, 25, 3, 122, 44, 77, 55, 105, 24, 112, 61, 14, 87, 102,
                                              34, 19, 71, 94},
                                              {73, 33, 14, 45, 95, 83, 1, 110, 52, 124, 16, 99, 115, 27, 64, 56, 2, 71,
                                              92, 126, 39, 101, 12, 53, 109, 116, 77, 41, 26, 22, 59, 82, 63, 36, 105,
                                              18, 121, 86, 11, 118, 46, 75, 66, 5, 89, 54, 103, 29, 125, 3, 47, 81, 76,
                                              15, 51, 102, 114, 28, 88, 108, 21, 57, 67, 38, 20, 34, 84, 106, 113, 42,
                                              91, 120, 98, 78, 55, 62, 7, 68, 8, 24, 79, 65, 10, 31, 60, 122, 6, 49, 43,
                                              32, 96, 85, 90, 23, 107, 119, 100, 40, 72, 112, 58, 4, 123, 93, 13, 111,
                                              50, 19, 37, 70, 25, 80, 44, 74, 17, 117, 87, 30, 94, 9, 69, 35, 48, 0, 61,
                                              127, 97, 104},
                                              {106, 116, 18, 98, 70, 7, 95, 125, 50, 9, 85, 59, 26, 45, 78, 34, 111, 83,
                                              94, 39, 4, 127, 48, 68, 75, 96, 28, 56, 20, 114, 8, 42, 122, 101, 47, 63,
                                              115, 6, 77, 29, 36, 17, 107, 87, 51, 11, 65, 93, 104, 55, 124, 37, 46,
                                              119, 91, 103, 13, 64, 79, 16, 30, 82, 61, 0, 120, 84, 71, 23, 27, 118, 88,
                                              57, 32, 15, 108, 52, 102, 40, 1, 72, 19, 66, 92, 24, 117, 60, 10, 105,
                                              123, 5, 49, 81, 33, 76, 41, 100, 109, 89, 31, 112, 69, 97, 126, 43, 54,
                                              14, 74, 86, 2, 58, 21, 35, 73, 62, 12, 113, 3, 121, 110, 44, 99, 38, 67,
                                              90, 80, 22, 25, 53},
                                              {25, 65, 83, 115, 76, 48, 10, 3, 47, 18, 110, 126, 98, 56, 90, 38, 99, 24,
                                              40, 72, 6, 84, 89, 69, 20, 54, 59, 33, 112, 12, 106, 120, 34, 15, 46, 2,
                                              16, 70, 101, 82, 61, 50, 118, 88, 79, 121, 104, 29, 0, 62, 22, 114, 26,
                                              75, 8, 123, 44, 107, 52, 71, 93, 100, 37, 86, 103, 51, 109, 39, 11, 57,
                                              119, 64, 95, 30, 42, 19, 73, 125, 1, 81, 9, 49, 87, 23, 91, 45, 7, 97, 68,
                                              32, 28, 124, 63, 108, 78, 117, 27, 80, 17, 77, 122, 41, 14, 5, 35, 113,
                                              67, 55, 102, 92, 105, 60, 36, 74, 96, 127, 43, 94, 4, 85, 21, 13, 111, 31,
                                              66, 116, 58, 53} };

    bitset<N> BitReordering(bitset<N>, int);

    bitset<N> SBox(bitset<N>, bitset<N>, int);

    bitset<N> EncCPA(bitset<N>, bitset<N>[], bitset<N>);
};


#endif //K_CIPHER_KCIPHER_H