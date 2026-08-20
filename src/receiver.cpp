#include "receiver.h"
#include "record.h"
#include "serializer.h"
#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstdint>

std::string transportMediumReceiver = "tm.bin";

Receiver::Receiver(AEAD aeadConfig, const std::vector<uint8_t>& key)
    : decrypter(aeadConfig, key) {
}

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

            std::vector<uint8_t> plainText, aad, tag;
            decrypter.Decrypt(byteStream, plainText, aad, tag);

            record = serializer.Deserialize(plainText);
            record.recId = serializer.GetRecIdFromAAD(aad);

            // recId is authenticated via AAD, so a set of previously-accepted
            // ids is a reliable replay check regardless of arrival order.
            if (seenRecIds.count(record.recId)) {
                throw std::runtime_error("Replay detected: record id already seen\n");
            }
            seenRecIds.insert(record.recId);

            return 0;
        }
    } catch (...) {
        return 1;
    }
    return 1;
}
