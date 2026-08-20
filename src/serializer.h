#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <vector>
#include "record.h"
#include <cstdint>


class Serializer {
    public:
        std::vector<uint8_t> Serialize(const Record& record);
        Record Deserialize(std::vector<uint8_t> byteStream);
        std::vector<uint8_t> GetAADBytes(uint32_t aad);
        uint32_t GetRecIdFromAAD(const std::vector<uint8_t>& aad);
};

#endif