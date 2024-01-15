#include <iostream>
#include <iomanip>
#include <cstring>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <chrono>

using namespace std;

// Function to convert a hexadecimal string to an integer
uint64_t hexToDec(const string& hexString) {
    stringstream ss;
    ss << hex << hexString;
    uint64_t result;
    ss >> result;
    return result;
}

// Function to convert an integer to a hexadecimal string
string decToHex(uint64_t dec) {
    stringstream ss;
    ss << hex << dec;
    return ss.str();
}

// Function to calculate hash160 of a compressed public key
string hash160(const string& compressedPubKey) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;

    // Parse the compressed public key
    if (secp256k1_ec_pubkey_parse(ctx, &pubkey, reinterpret_cast<const unsigned char*>(compressedPubKey.c_str()), compressedPubKey.length()) != 1) {
        cerr << "Error parsing compressed public key." << endl;
        exit(EXIT_FAILURE);
    }

    // Compute hash160
    unsigned char hash[20];
    size_t output_len = 20;
    if (secp256k1_ec_pubkey_serialize(ctx, hash, &output_len, &pubkey, SECP256K1_EC_COMPRESSED) != 1) {
        cerr << "Error serializing public key." << endl;
        exit(EXIT_FAILURE);
    }

    secp256k1_context_destroy(ctx);

    return string(hash, hash + output_len);
}

ll mod_pow(ll base, ll exponent, ll mod) {
    ll result = 1;
    base %= mod;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % mod;
        base = (base * base) % mod;
        exponent /= 2;
    }
    return result;
}

ll bsgs(const string& target, const string& mod, ll start, ll end) {
    ll m = ceil(sqrt(end - start));
    unordered_map<string, ll> baby_steps;

    // Precompute baby steps
    auto baby_steps_start = chrono::high_resolution_clock::now();
    string cur = decToHex(start);
    for (ll i = start; i < end; ++i) {
        baby_steps[hash160(cur)] = i;
        cur = decToHex((hexToDec(cur) + 1) % hexToDec(mod));
    }
    auto baby_steps_end = chrono::high_resolution_clock::now();
    chrono::duration<double> baby_steps_duration = baby_steps_end - baby_steps_start;
    cout << "Baby steps precomputation time: " << baby_steps_duration.count() << " seconds" << endl;

    // Compute giant steps
    ll giant_step = mod_pow(2, m * (mod.length() - 2), hexToDec(mod)); // Fermat's Little Theorem
    string giant_cur = target;

    // Check giant steps against precomputed baby steps
    auto search_start = chrono::high_resolution_clock::now();
    for (ll j = 0; j < m; ++j) {
        if (baby_steps.find(giant_cur) != baby_steps.end()) {
            auto search_end = chrono::high_resolution_clock::now();
            chrono::duration<double> search_duration = search_end - search_start;
            cout << "Discrete logarithm found in " << search_duration.count() << " seconds" << endl;
            return j * m + baby_steps[giant_cur];
        }
        giant_cur = decToHex((hexToDec(giant_cur) * giant_step) % hexToDec(mod));
    }
    auto search_end = chrono::high_resolution_clock::now();
    chrono::duration<double> search_duration = search_end - search_start;
    cout << "Search time: " << search_duration.count() << " seconds" << endl;

    return -1; // No match found
}

int main() {
    string compressedPubKey, mod;
    cout << "Enter compressed public key and mod (in hexadecimal): ";
    cin >> compressedPubKey >> mod;

    ll start = 1ull << 65; // 2^65
    ll end = 1ull << 66;   // 2^66

    cout << "Searching for discrete logarithm in the range " << start << " to " << end << endl;

    auto overall_start = chrono::high_resolution_clock::now();
    ll result = bsgs(hash160(compressedPubKey), mod, start, end);
    auto overall_end = chrono::high_resolution_clock::now();
    chrono::duration<double> overall_duration = overall_end - overall_start;
    cout << "Overall execution time: " << overall_duration.count() << " seconds" << endl;

    if (result != -1) {
        cout << "Discrete logarithm x in base^x â¡ target (mod mod) is: " << result << endl;
    } else {
        cout << "No solution found in the specified range." << endl;
    }

    return 0;
}
