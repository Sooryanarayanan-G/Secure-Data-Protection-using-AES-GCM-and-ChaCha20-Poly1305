#include "record.h"
#include <vector>
#include "serializer.h"
#include <cstdint>


std::vector<uint8_t> Serializer::Serialize(const Record& record) {
    std::vector<uint8_t> byteStream;

    int64_t timeStamp = (int64_t) record.timestamp;
    for (int i = 0; i < 8; i ++) {
        byteStream.push_back( (timeStamp >> (56 - 8 * i) ) & 0xFF );
    }

    int32_t dataSize = (int32_t) record.data.size();
    for (int i = 0; i < 4; i ++) {
        byteStream.push_back( (dataSize >> (24 - 8 * i) ) & 0xFF );
    }

    std::string data = record.data;
    for (int i = 0; i < dataSize; i ++) {
        byteStream.push_back( static_cast<uint8_t> (data[i]) );
    }

    return byteStream;
}

Record Serializer::Deserialize(std::vector<uint8_t> byteStream) {
    int64_t timeStamp = 0;
    int i = 0;
    for (; i < 8; i++) {
        timeStamp = (timeStamp << 8) | byteStream[i];
    }

    int32_t dataSize = 0;
    for (; i < 12; i++) {
        dataSize = (dataSize << 8) | byteStream[i];
    }

    std::string data;
    for (; i < dataSize + 12; i++) {
        data.push_back(static_cast<char> (byteStream[i]));
    }

    Record record{0, timeStamp, data};
    return record;
}

std::vector<uint8_t> Serializer::GetAADBytes(uint32_t aad) {
    std::vector<uint8_t> byteStream;

    for (int i = 0; i < 4; i ++) {
        byteStream.push_back( (aad >> (24 - 8 * i) ) & 0xFF );
    }

    return byteStream;
}

uint32_t Serializer::GetRecIdFromAAD(const std::vector<uint8_t>& aad) {
    uint32_t recId = 0;
    for (int i = 0; i < 4; i++) {
        recId = (recId << 8) | aad[i];
    }
    return recId;
}
