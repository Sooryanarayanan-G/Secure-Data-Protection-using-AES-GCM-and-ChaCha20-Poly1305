#include "sender.h"
#include "receiver.h"
#include "crypt.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <set>
#include <random>
#include <iomanip>

using namespace std;

// Must match the wire-format constants in crypt.cpp: AAD(4) || nonce(12) || ciphertext || tag(16).
static const size_t WIRE_AAD_LEN = 4;
static const size_t WIRE_NONCE_LEN = 12;

static const string transportMedium = "tm.bin";
static int totalTests = 0, passedTests = 0;

static void Report(const string& trId, const string& name, bool pass, const string& detail = "") {
    totalTests++;
    if (pass) passedTests++;
    cout << "[" << (pass ? "PASS" : "FAIL") << "] " << trId << " - " << name;
    if (!detail.empty()) cout << " (" << detail << ")";
    cout << endl;
}

static string AlgoName(AEAD a) {
    return a == aes_128_gcm ? "AES-128-GCM" : "ChaCha20-Poly1305";
}

static vector<uint8_t> MakeKey(AEAD algo, uint8_t fill) {
    size_t len = (algo == aes_128_gcm) ? 16 : 32;
    return vector<uint8_t>(len, fill);
}

// Simulates a malicious actor flipping one byte of the protected record in transit.
static void CorruptByteAt(size_t offset) {
    fstream f(transportMedium, ios::in | ios::out | ios::binary);
    f.seekg(offset);
    char b;
    f.read(&b, 1);
    b ^= 0xFF;
    f.seekp(offset);
    f.write(&b, 1);
}

static size_t FileSize() {
    ifstream f(transportMedium, ios::binary | ios::ate);
    return f.tellg();
}

// ---- TR-1: Positive baseline ----
static void RunTR1_Baseline(AEAD algo) {
    auto key = MakeKey(algo, 0xA1);
    Sender sender(algo, key);
    Receiver receiver(algo, key);
    string msg = "TR-1 baseline message for " + AlgoName(algo);
    sender.Send(msg);
    string received = receiver.Receive();
    Report("TR-1", "Positive baseline (" + AlgoName(algo) + ")", received == msg);
}

// ---- TR-2: Ciphertext integrity ----
static void RunTR2_CiphertextTamper(AEAD algo) {
    auto key = MakeKey(algo, 0xA2);
    Sender sender(algo, key);
    Receiver receiver(algo, key);
    sender.Send("TR-2 ciphertext tamper test");
    CorruptByteAt(WIRE_AAD_LEN + WIRE_NONCE_LEN); // first byte of ciphertext
    string received = receiver.Receive();
    Report("TR-2", "Ciphertext integrity (" + AlgoName(algo) + ")", received.empty());
}

// ---- TR-3: Authentication tag ----
static void RunTR3_TagTamper(AEAD algo) {
    auto key = MakeKey(algo, 0xA3);
    Sender sender(algo, key);
    Receiver receiver(algo, key);
    sender.Send("TR-3 tag tamper test");
    CorruptByteAt(FileSize() - 1); // last byte falls within the 16-byte tag
    string received = receiver.Receive();
    Report("TR-3", "Authentication tag (" + AlgoName(algo) + ")", received.empty());
}

// ---- TR-4: Associated Data (AAD) ----
static void RunTR4_AADTamper(AEAD algo) {
    auto key = MakeKey(algo, 0xA4);
    Sender sender(algo, key);
    Receiver receiver(algo, key);
    sender.Send("TR-4 AAD tamper test");
    CorruptByteAt(0); // first byte of the 4-byte AAD
    string received = receiver.Receive();
    Report("TR-4", "AAD integrity (" + AlgoName(algo) + ")", received.empty());
}

// ---- TR-5: Replay ----
static void RunTR5_Replay(AEAD algo) {
    auto key = MakeKey(algo, 0xA5);
    Sender sender(algo, key);
    Receiver receiver(algo, key);
    string msg = "TR-5 replay test";
    sender.Send(msg);
    string first = receiver.Receive();
    // Attacker resubmits the exact same captured protected record; no new Send() happens.
    string replay = receiver.Receive();
    Report("TR-5", "Replay handling (" + AlgoName(algo) + ")", first == msg && replay.empty());
}

// ---- TR-6: Wrong key ----
static void RunTR6_WrongKey(AEAD algo) {
    auto correctKey = MakeKey(algo, 0xA6);
    auto wrongKey = MakeKey(algo, 0xB6);
    Sender sender(algo, correctKey);
    Receiver receiver(algo, wrongKey);
    sender.Send("TR-6 wrong key test");
    string received = receiver.Receive();
    Report("TR-6", "Wrong-key rejection (" + AlgoName(algo) + ")", received.empty());
}

// ---- TR-7: Nonce management verification ----
static void RunTR7_NonceUniqueness(AEAD algo, int count) {
    auto key = MakeKey(algo, 0xA7);
    Sender sender(algo, key);
    set<vector<uint8_t>> seenNonces;
    bool duplicateFound = false;

    for (int i = 0; i < count; i++) {
        sender.Send("nonce-test-record-" + to_string(i));
        
        ifstream f(transportMedium, ios::binary);
        vector<uint8_t> nonce(WIRE_NONCE_LEN);
        f.seekg(WIRE_AAD_LEN);
        f.read((char*)nonce.data(), WIRE_NONCE_LEN);
        
        if (!seenNonces.insert(nonce).second) {
            duplicateFound = true;
            break;
        }

        // Optional print stmts to see that the program is still running properly
        if (i > 0 && i % 1000 == 0)
            std::cout << "No reuse detected till " << i <<"th iteration" << std::endl;
    }

    Report("TR-7", "Nonce uniqueness over " + to_string(count) + " records (" + AlgoName(algo) + ")",
           !duplicateFound && (int)seenNonces.size() == count,
           to_string(seenNonces.size()) + " unique nonces observed");
}

// ---- TR-8: Performance evaluation ----
static void RunTR8_Performance() {
    cout << "\n--- TR-8: Performance Evaluation ---" << endl;

    vector<pair<string, size_t>> sizes = {{"64 B", 64}, {"1 KiB", 1024}, {"64 KiB", 65536}};
    vector<AEAD> algos = {aes_128_gcm, chacha20_poly1305};
    mt19937 rng(42);

    cout << left << setw(20) << "Algorithm" << setw(10) << "Size"
         << setw(18) << "Encrypt (us/op)" << setw(18) << "Decrypt (us/op)"
         << setw(16) << "Enc MB/s" << "Dec MB/s" << endl;

    for (auto& sizePair : sizes) {
        int iters = (sizePair.second >= 65536) ? 500 : 2000;

        for (auto algo : algos) {
            auto key = MakeKey(algo, 0xC0);
            Crypt crypt(algo, key);

            vector<uint8_t> plain(sizePair.second);
            for (auto& b : plain) b = (uint8_t)rng();
            vector<uint8_t> aad = {0, 0, 0, 1};

            vector<Bytes> secureStreams;
            secureStreams.reserve(iters);

            auto encStart = chrono::high_resolution_clock::now();
            for (int i = 0; i < iters; i++) {
                secureStreams.push_back(crypt.Encrypt(plain, aad));
            }
            auto encEnd = chrono::high_resolution_clock::now();

            auto decStart = chrono::high_resolution_clock::now();
            for (int i = 0; i < iters; i++) {
                Bytes out, outAad, tag;
                crypt.Decrypt(secureStreams[i], out, outAad, tag);
            }
            auto decEnd = chrono::high_resolution_clock::now();

            double encUs = chrono::duration<double, micro>(encEnd - encStart).count() / iters;
            double decUs = chrono::duration<double, micro>(decEnd - decStart).count() / iters;
            double encMBs = (sizePair.second / (encUs / 1e6)) / (1024.0 * 1024.0);
            double decMBs = (sizePair.second / (decUs / 1e6)) / (1024.0 * 1024.0);

            cout << left << setw(20) << AlgoName(algo) << setw(10) << sizePair.first
                 << fixed << setprecision(2)
                 << setw(18) << encUs << setw(18) << decUs
                 << setw(16) << encMBs << decMBs << endl;
        }
    }
}

int main() {
    cout << "==================================================" << endl;
    cout << " CS6530 Assignment 1 - AEAD Test Suite" << endl;
    cout << " TR-1..TR-6 run for both AES-128-GCM and ChaCha20-Poly1305" << endl;
    cout << "==================================================" << endl;

    vector<AEAD> algos = {aes_128_gcm, chacha20_poly1305};
    for (auto algo : algos) {
        cout << "\n--- Configuration: " << AlgoName(algo) << " ---" << endl;
        RunTR1_Baseline(algo);
        RunTR2_CiphertextTamper(algo);
        RunTR3_TagTamper(algo);
        RunTR4_AADTamper(algo);
        RunTR5_Replay(algo);
        RunTR6_WrongKey(algo);
    }

    cout << "\n--- TR-7: Nonce Management Verification ---" << endl;
    for (auto algo : algos) {
        RunTR7_NonceUniqueness(algo, 10000);
    }

    RunTR8_Performance();

    cout << "\n==================================================" << endl;
    cout << passedTests << "/" << totalTests << " correctness tests passed." << endl;
    cout << "==================================================" << endl;

    return (passedTests == totalTests) ? 0 : 1;
}
