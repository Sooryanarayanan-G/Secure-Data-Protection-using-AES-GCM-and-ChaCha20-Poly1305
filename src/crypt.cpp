#include "crypt.h"
#include <vector>
#include <cstdint>

using namespace std;

Crypt::Crypt(AEAD aeadConfig, vector<uint8_t> userkey) {
    key = userkey;
}

void Crypt::Encrypt (const Bytes& plainText,
                     const Bytes& nonce,
                     Bytes& cipherText,
                     Bytes& tag) {
                        
}