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
    
    if (argc != 3) {
        std::cout << "Usage: ./a.out <data> <keyfile.bin>" << std::endl;
        return 1;
    }

    std::string dataSent = argv[1];
    std::vector<uint8_t> key = GetKey(argv[2]);
    AEAD aeadConfig = aes_128_gcm;

    // Sender and Receiver objects
    Sender senderObject (aeadConfig, key);
    Receiver receiverObject;

    senderObject.Send(dataSent);
    
    std::string data = receiverObject.Receive();
    std::cout << data << std::endl;

    return 0;
}  