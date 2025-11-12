#ifndef RSA_H
#define RSA_H

#include <cstdint>
#include <ctime>
#include <gmpxx.h>
#include <vector>
#include <fstream>

void mpzToBytes256(const mpz_class& num, std::vector<uint8_t>& bytes) {
    size_t count;
    uint8_t* data = (uint8_t*)mpz_export(NULL, &count, -1, 1, 1, 0, num.get_mpz_t());
    uint8_t* it = data;
    int i = 0;
    for (; i < count; ++i) {
        bytes.push_back(*it++);
    }
    for (; i < 256; ++i) {
        bytes.push_back(0);
    }
    free(data);
}

void bytesToMpz256(std::vector<uint8_t>& bytes, mpz_class& num) {
    mpz_t result;
    mpz_init(result);
    std::vector<uint8_t> t_v(256);
    size_t sz = bytes.size() - 256;
    for (int i = 0; i < 256; ++i) {
        t_v[i] = bytes[sz + i];
    }
    bytes.resize(bytes.size() - 256);
    mpz_import(result, t_v.size(), -1, 1, 1, 0, t_v.data());
    num = mpz_class(result);
    mpz_clear(result);
}

class RSA_server {
private:
    mpz_class p, q, N, S, d, e;
    gmp_randclass rng;

    void get_random_prime(const mpz_class& lower_bound, const mpz_class& upper_bound, mpz_class& res) {
        mpz_class range = upper_bound - lower_bound;

        do {
            res = rng.get_z_range(range) + lower_bound;
        } while (!mpz_probab_prime_p(res.get_mpz_t(), 50));
    }

    void create_field_and_roots() {
        mpz_class lower_bound, upper_bound, two_in_2048;

        mpz_ui_pow_ui(lower_bound.get_mpz_t(), 2, 1023);
        mpz_ui_pow_ui(upper_bound.get_mpz_t(), 2, 1024);

        get_random_prime(lower_bound, upper_bound, p);
        get_random_prime(lower_bound, upper_bound, q);

        N = p * q;

        S = (p - 1) * (q - 1);

        e = 65537;
        mpz_invert(d.get_mpz_t(), e.get_mpz_t(), S.get_mpz_t());
        //TODO? if (d == 0)


        std::ofstream ofs("RSA_server.dat", std::ios::binary);
        mpz_class t = p; t <<= 1024; t += q;
        std::vector<uint8_t> v_pq; v_pq.reserve(256);
        mpzToBytes256(t, v_pq);
        if (ofs) {
            ofs.write(reinterpret_cast<const char*>(v_pq.data()), 256);
            ofs.close();
        }
    }

    bool restore_field_and_roots() {
        std::ifstream ifs("RSA_server.dat", std::ios::binary);

        if (!ifs) {
            return false;
        }

        std::vector<uint8_t> v_pq; v_pq.resize(256);
        try {
            ifs.read(reinterpret_cast<char*>(v_pq.data()), 256);
            ifs.close();
        } catch(...) { return false; }

        mpz_class t;
        bytesToMpz256(v_pq, t);
        mpz_class one_1024;
        for (int i = 0; i < 1024; ++i) {
            mpz_setbit(one_1024.get_mpz_t(), i);
        }
        q = t & one_1024;
        p = t >> 1024;
        N = p * q;
        S = (p - 1) * (q - 1);
        e = 65537;
        mpz_invert(d.get_mpz_t(), e.get_mpz_t(), S.get_mpz_t());

        return true;
    }

public:
    explicit RSA_server() :rng(gmp_randinit_default) {
        rng.seed(time(nullptr));
        if (!restore_field_and_roots()) {
            create_field_and_roots();
        }
    }

    inline const mpz_class& get_field() const { return N; }
    //inline const mpz_class& get_public_key() const { return e; }


    void sign_msg(const mpz_class& msg, std::vector<uint8_t>& bytes) const {
        bytes.clear();
        mpz_class t_msg1, t_msg2;
        if (msg < N) {
            mpz_powm(t_msg2.get_mpz_t(), msg.get_mpz_t(), d.get_mpz_t(), N.get_mpz_t());
            mpzToBytes256(t_msg2, bytes);
            return;
        }

        mpz_class one_1024, one_2048, two_in_1024;
        for (int i = 0; i < 1024; ++i) {
            mpz_setbit(one_1024.get_mpz_t(), i);
        }

        mpz_ui_pow_ui(two_in_1024.get_mpz_t(), 2, 1024);

        t_msg1 = msg;
        do {
            t_msg2 = t_msg1 & one_1024;
            mpz_powm(t_msg2.get_mpz_t(), t_msg2.get_mpz_t(), d.get_mpz_t(), N.get_mpz_t());
            mpzToBytes256(t_msg2, bytes);
            t_msg1 >>= 1024;
        } while (t_msg1 > two_in_1024);

        mpz_powm(t_msg1.get_mpz_t(), t_msg1.get_mpz_t(), d.get_mpz_t(), N.get_mpz_t());
        mpzToBytes256(t_msg1, bytes);
    }
};

namespace RSA_client {

bool check_sign(std::vector<uint8_t>& sign, const mpz_class& msg,
                const mpz_class& field) {
    mpz_class dec_msg, t_msg1;
    mpz_class public_key = 65537;

    do {
        bytesToMpz256(sign, t_msg1);
        mpz_powm(t_msg1.get_mpz_t(), t_msg1.get_mpz_t(), public_key.get_mpz_t(), field.get_mpz_t());
        dec_msg <<= 1024;
        dec_msg |= t_msg1;

    } while (sign.size() > 255);


    if (dec_msg == msg)
        return true;
    else
        return false;
}

}

#endif // RSA_H
