#include <iostream>

using namespace std;

int main() {
    uint8_t sbox[256];
    uint8_t p = 1, q = 1;
    do {
        /* multiply p by 3 */
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

        /* divide q by 3 (equals multiplication by 0xf6) */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;

        /* compute the affine transformation */
        uint8_t xformed = q;

        sbox[p] = xformed ^ 0x63;
    } while (p != 1);
    sbox[0] = 0x63;
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++)
            cout << hex << (int) sbox[16 * i + j] << "\t";
        cout << endl;
    }

    cout << endl;
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++)
            cout << hex << (int) sbox[16 * i + j] * (16 * i + j + 1) % 256<< "\t";
        cout << endl;
    }
    return 0;
}

