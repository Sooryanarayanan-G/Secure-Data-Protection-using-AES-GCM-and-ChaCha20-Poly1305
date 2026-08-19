#include "record.h"
#include "sender.h"
#include "receiver.h"
#include <string>
#include <iostream>
#include <fstream>
#include <cstdint>

std::vector<uint8_t> GetKey(std::string filename) {
    std::ifstream file (filename, std::ios::binary);
    
    if (!file.is_open()) {
        return {};
    } 
    
    file.seekg(0, std::ios::end);
    int size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> key(size);
    file.read((char*)key.data(), size);
    
    return key;
}

int main(int argc, char* argv[]) {
    
    if (argc != 4) {
        std::cout << "Usage: ./a.out <data> <enc-type> <keyfile.bin>" << std::endl;
        return 1;
    }

    std::string dataSent = argv[1];
    std::vector<uint8_t> key = GetKey(argv[3]);
    AEAD aeadConfig = (argv[2] == "aes") ? aes_128_gcm:chacha20_poly1305;

    // Sender and Receiver objects
    Sender senderObject (aeadConfig, key);
    Receiver receiverObject;

    senderObject.Send(dataSent);
    
    // std::string data = receiverObject.Receive();
    // std::cout << data << std::endl;

    return 0;
}  