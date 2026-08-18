#include <iostream>
#include "sender.h"
#include "record.h"
#include <string>
#include <time.h>
#include <fstream>
#include "serializer.h"
#include "crypt.h"
#include <cstdint>


using namespace std;

// A common file, to which the sender writes and the receiver reads from.
std::string transportMediumSender = "tm.bin";

// Sender owns a Serializer and an Encrypter.
Sender::Sender(AEAD aeadConfig, const vector<uint8_t>& key) 
    : serializer(), encrypter(aeadConfig, key) {
}

// Takes as parameter a record, serializes it, and writes to the common file.
int Sender::SendRecord(Record& record) {
    try {
        ofstream file(transportMediumSender);
        if (file.is_open()) {
            vector<uint8_t> byteStream = serializer.Serialize(record);  // Serialization of record.
            for (uint8_t byte: byteStream) {
                file.put(byte);
            }
        } else return 1;
    } catch (const exception& e) {
        cout << e.what() << endl;
    } catch (...) {
        return 1;
    }
    return 0;
}

// Creates a record out of the data to be sent and the timestamp recorded.
Record Sender::CreateRecord(const string& data, time_t timeStamp) {
    Record record{timeStamp, data};
    return record;
}

// The only top level function which the user can access to send data.
int Sender::Send(string data) {
    try {
        time_t sentTime = time(nullptr);
        Record record = CreateRecord(data, sentTime);
        return SendRecord(record);
    } catch (...) {
        return 1;
    }
}

