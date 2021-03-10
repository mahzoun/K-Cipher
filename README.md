# K-Cipher
Cryptanalysis of so called strong PUF
----------
Κ-Cipher: A Low Latency, Bit Length Parameterizable Cipher
Michael Kounavis and Sergej Deutsch and Santosh Ghosh and David Durham.
It works as follow:    


```asm
KCipher(x, n, K0, K1, K2, r)
    u = x + C
    v = u + K0
    u = BitReordering(v, n, 0)
    v = SBox(u, n, Flex, ⊥, ⊥)
    u = u + K1
    v = BitReordering(v, n, 1)
    u = SBox(u, n, Flex, ⊥, ⊥)
    v = u + K2
    u = BitReordering(v, n, 2)
    v = SBox(u, n, Flex, ⊥, ⊥)
    veil = BitReordering(K2, n, 3)
    y = v xor veil 
    return y
```










##References
https://eprint.iacr.org/2020/030.pdf



