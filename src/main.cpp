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

void PrintUsage() {
    std::cout << "Usage:\n"
              << "  ./demo send <data> <aes|chacha> <keyfile.bin>\n"
              << "  ./demo recv <aes|chacha> <keyfile.bin>\n";
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "send") {
        if (argc != 5) {
            PrintUsage();
            return 1;
        }
        std::string dataSent = argv[2];
        std::vector<uint8_t> key = GetKey(argv[4]);
        AEAD aeadConfig = (std::string(argv[3]) == "aes") ? aes_128_gcm : chacha20_poly1305;

        Sender senderObject (aeadConfig, key);
        senderObject.Send(dataSent);
        std::cout << "Sent. Protected record written to tm.bin." << std::endl;

    } else if (mode == "recv") {
        if (argc != 4) {
            PrintUsage();
            return 1;
        }
        std::vector<uint8_t> key = GetKey(argv[3]);
        AEAD aeadConfig = (std::string(argv[2]) == "aes") ? aes_128_gcm : chacha20_poly1305;

        Receiver receiverObject (aeadConfig, key);
        std::string data = receiverObject.Receive();
        if (data.empty()) {
            std::cout << "Rejected: authentication or replay check failed." << std::endl;
        } else {
            std::cout << data << std::endl;
        }

    } else {
        PrintUsage();
        return 1;
    }

    return 0;
}
