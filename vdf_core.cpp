#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <random>
#include <iomanip>
#include <sstream>

// openssl libs
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// --- SETTINGS config ---
const double SLOT_WIDTH = 0.1;
const int NUM_SLOTS = 10;
const double START_DELAY = 5.0; // wait 5s for network jitter
const size_t PACKET_SIZE = 128; // MTU size for monero p2p

// ill use this for checking if the hex is right
std::string debug_hex(const std::vector<uint8_t> &data)
{
    std::stringstream ss;
    for (auto b : data)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

struct RevealPkg
{
    std::vector<uint8_t> proof;
    std::vector<uint8_t> salt;
    int idx;
};

struct PulseEvent
{
    double time;
    std::vector<uint8_t> blob;
    RevealPkg info;
};

class GhostNode_Research_v15
{
private:
    uint8_t node_secret[32];

    // manual poisson dist because i dont want use std::poisson_distribution
    // it maybe can behave weird on different compilers...
    int get_k_value(double lambda)
    {
        double L = std::exp(-lambda);
        double p = 1.0;
        int k = 0;

        static std::mt19937_64 engine(std::random_device{}());
        std::uniform_real_distribution<double> dist(0.0, 1.0);

        while (p > L)
        {
            k++;
            p *= dist(engine);
        }
        return (k - 1 > 0) ? k - 1 : 1;
    }

    // derive epoch key so identity is hiden from ISP but still deterministic i guess
    std::vector<uint8_t> get_epoch_key(const std::string &block_hash)
    {
        std::vector<uint8_t> key_out(32);
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

        if (EVP_PKEY_derive_init(ctx) <= 0)
            EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, (const uint8_t *)block_hash.c_str(), block_hash.length());
        EVP_PKEY_CTX_set1_hkdf_key(ctx, node_secret, 32);
        EVP_PKEY_CTX_add1_hkdf_info(ctx, (const uint8_t *)"ghost-v15", 9);

        size_t len = 32;
        EVP_PKEY_derive(ctx, key_out.data(), &len);
        EVP_PKEY_CTX_free(ctx);
        return key_out;
    }

public:
    GhostNode_Research_v15()
    {
        RAND_bytes(node_secret, 32);
    }

    std::vector<PulseEvent> generate_traffic(std::string epoch_id, std::string prev_hash)
    {
        auto key = get_epoch_key(prev_hash);
        int p_count = get_k_value(2.0); // lam=2 is good for noise

        std::vector<PulseEvent> batch;
        for (int i = 0; i < p_count; i++)
        {
            // 1. the commit
            std::vector<uint8_t> proof_val = {'O', 'K', '_', 'V', 'D', 'F'};
            std::vector<uint8_t> salt_val(32);
            RAND_bytes(salt_val.data(), 32);

            SHA256_CTX hash_obj;
            SHA256_Init(&hash_obj);
            SHA256_Update(&hash_obj, proof_val.data(), proof_val.size());
            SHA256_Update(&hash_obj, salt_val.data(), salt_val.size());
            SHA256_Update(&hash_obj, epoch_id.c_str(), epoch_id.length());
            std::string s_idx = std::to_string(i);
            SHA256_Update(&hash_obj, s_idx.c_str(), s_idx.length());

            std::vector<uint8_t> h_out(32);
            SHA256_Final(h_out.data(), &hash_obj);

            // 2. timing logic (deterministic slots)
            std::string label = "slot_" + std::to_string(i);
            uint8_t entropy[32];
            unsigned int out_len;
            HMAC(EVP_sha256(), key.data(), 32, (uint8_t *)label.c_str(), label.length(), entropy, &out_len);

            // pick slot from first 4 byte of hmac
            uint32_t raw_val = *(uint32_t *)entropy;
            int slot_idx = raw_val % NUM_SLOTS;

            // add jitter so ISP cant see sharp spike
            int j_val;
            RAND_bytes((uint8_t *)&j_val, 4);
            double jitter = (std::abs(j_val) % 100) / 1000.0;

            double send_at = START_DELAY + (slot_idx * SLOT_WIDTH) + jitter;

            // 3. build the blob
            std::vector<uint8_t> packet(PACKET_SIZE);
            RAND_bytes(packet.data(), PACKET_SIZE); // fill noise first

            uint8_t nonce[12];
            RAND_bytes(nonce, 12);

            // i use manual loop copy because i dont trust std::copy for raw bytes here
            for (int j = 0; j < 12; j++)
                packet[j] = nonce[j];
            for (int j = 0; j < 32; j++)
                packet[j + 12] = h_out[j];

            batch.push_back({send_at, packet, {proof_val, salt_val, i}});
        }
        return batch;
    }
};

int main()
{
    GhostNode_Research_v15 test_node;
    std::string eid = "ep_100_test";
    std::string b_hash = "0000abc_fake_hash";

    auto pulses = test_node.generate_traffic(eid, b_hash);

    std::cout << "DEBUG: count=" << pulses.size() << " pulses out" << std::endl;
    for (auto &p : pulses)
    {
        std::cout << " -> time=" << p.time << " | commit=";
        for (int k = 12; k < 18; k++)
            printf("%02x", p.blob[k]);
        std::cout << "..." << std::endl;

        // --- TODO: REMOVE ---
        SHA256_CTX v_check;
        SHA256_Init(&v_check);
        SHA256_Update(&v_check, p.info.proof.data(), p.info.proof.size());
        SHA256_Update(&v_check, p.info.salt.data(), p.info.salt.size());
        SHA256_Update(&v_check, eid.c_str(), eid.length());
        std::string i_str = std::to_string(p.info.idx);
        SHA256_Update(&v_check, i_str.c_str(), i_str.length());
        uint8_t v_res[32];
        SHA256_Final(v_res, &v_check);

        if (memcmp(v_res, p.blob.data() + 12, 32) == 0)
        {
            std::cout << "    (local verify: ok)" << std::endl;
        }
        else
        {
            std::cout << "    (local verify: ERR!! CHECK LOGS)" << std::endl;
        }
        // ----------------------------------------
    }

    return 0;
}