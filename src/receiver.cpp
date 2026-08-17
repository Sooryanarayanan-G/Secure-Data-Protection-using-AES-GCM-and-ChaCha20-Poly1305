#include "receiver.h"
#include "record.h"
#include "serializer.h"
#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstdint>

std::string transportMediumReceiver = "tm.bin";

std::string Receiver::Receive() {
    Record record{};
    int returnCode = ConstructRecord(record);
    if (returnCode) return "";
    return record.data;
}

int Receiver::ConstructRecord(Record& record) {
    try {
        std::ifstream file (transportMediumReceiver);
        Serializer serializer;
        if (file.is_open()) {
            file.seekg(0, std::ios::end);
            int size = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> byteStream(size);
            file.read((char*)byteStream.data(), size);
            record = serializer.Deserialize(byteStream);
            return 0;
        }
    } catch (...) {
        return 1;
    }
    return 1;
}
