#ifndef DIFFIEHELLMAN_H
#define DIFFIEHELLMAN_H

#include <ctime>
#include <gmpxx.h>

class DiffieHellman {
private:
    //поле, первообразный корень, секретный ключ, публичный ключ, общий ключ
    mpz_class p, g, sk, pk, ck;

    gmp_randclass rng;


    void get_random(const mpz_class& lower_bound, const mpz_class& upper_bound, mpz_class& res) {
        mpz_class range = upper_bound - lower_bound;
        res = rng.get_z_range(range) + lower_bound;
    }

    //генерируем поле и его первообразный корень
    void create_field_and_root() {
        /*mpz_class lower_bound, upper_bound, range, lower_bound_g, upper_bound_g, range_g, q, t;

        mpz_ui_pow_ui(lower_bound.get_mpz_t(), 2, 2047);
        mpz_ui_pow_ui(upper_bound.get_mpz_t(), 2, 2048);
        range = upper_bound - lower_bound;

        do {
            p = rng.get_z_range(range) + lower_bound;
        } while (mpz_probab_prime_p(p.get_mpz_t(), 50) == 0);

        q = (p - 1) / 2;
        g = 2;
        while (true) {
            if (mpz_probab_prime_p(g.get_mpz_t(), 50) == 0) {
                ++g;
                continue;
            }

            mpz_powm(t.get_mpz_t(), g.get_mpz_t(), q.get_mpz_t(), p.get_mpz_t());
            if (t != 1) {
                break;
            }
            ++g;
        }*/


        //2048-bit MODP Group
        //This group is assigned id 14.
        //This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
        std::string hex_str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                              "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                              "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                              "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                              "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                              "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                              "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                              "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                              "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                              "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                              "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
        p.set_str(hex_str, 16);
        g = 2;
        //условие g^((p-1)/2) mod p != 1 не выполняется
    }

    //генерирует приватный ключ, и по нему публичный
    void create_public_key() {
        mpz_class lower_bound, upper_bound;

        mpz_ui_pow_ui(lower_bound.get_mpz_t(), 2, 256);
        upper_bound = p - 2;
        get_random(lower_bound, upper_bound, sk);

        mpz_powm(pk.get_mpz_t(), g.get_mpz_t(), sk.get_mpz_t(), p.get_mpz_t());
    }


public:
    inline const mpz_class& get_field() const { return p; }
    inline const mpz_class& get_root() const { return g; }
    inline const mpz_class& get_public_key() const { return pk; }

    inline const mpz_class& get_common_key() const { return ck; }

    //получаем общий секрет по публичному ключу другой стороны
    void create_common_key(const mpz_class& other_pk) {
        mpz_powm(ck.get_mpz_t(), other_pk.get_mpz_t(), sk.get_mpz_t(), p.get_mpz_t());
    }

    explicit DiffieHellman() : rng(gmp_randinit_default) {
        rng.seed(time(nullptr));
        create_field_and_root();

        //выложить p, g в открытый доступ
        //и записать их на диск

        create_public_key();
    }

    explicit DiffieHellman(const mpz_class& field, const mpz_class& root, const mpz_class& other_pk)
        : p(field), g(root), rng(gmp_randinit_default) {
        rng.seed(time(nullptr));
        do {
            create_public_key();
        } while (other_pk == pk);
    }

    explicit DiffieHellman(const mpz_class& other_pk) : rng(gmp_randinit_default) {
        rng.seed(time(nullptr));
        std::string hex_str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                              "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                              "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                              "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                              "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                              "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                              "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                              "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                              "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                              "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                              "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
        p.set_str(hex_str, 16);
        g = 2;
        do {
            create_public_key();
        } while (other_pk == pk);
    }
};

#endif // DIFFIEHELLMAN_H
