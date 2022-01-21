# Cryptanalysis of K-Cipher

----------
This project is a c++ implementation of differential cryptanalysis attack to [K-Cipher](https://eprint.iacr.org/2020/030.pdf).
The project contains the following files;    
* `KCipher.h`: Includes headers for the functions of K-Cipher.
* `KCipher.cpp`: Includes the implemenation of the functions of K-Cipher.
* `main.cpp`: Includes the attack.
* `CMakeLists.txt`: cmake file for running the code

   
###Run the attack
To run the attack, run the following commands in the root directory of the project:
```bash
cmake .
make
./K_Cipher
```
Please note that the code is only tested on Ubuntu machine (`5.13.0-27-generic x86_64`). To run on other platforms please make sure that the 
randomness generation has enough entropy.    



