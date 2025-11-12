#ifndef UOV_H
#define UOV_H

#define _CRT_RAND_S
#include "Matrix.h"
#include "SHA.h"
#include <cstdint>
#include <cmath>
#include <vector>
#include <gmpxx.h>

#define Q 31
#define N 51
#define R 17
#define K 23

namespace UOV {

const int one_symb_sz = floor(log2(Q));                 //сколько бит можем считать в переменную
const int cert_sz = K * one_symb_sz;                    //размер сертификата
const int cnt_parts = ceil(256.0 / one_symb_sz);        //на сколько блоков бьется сообщение
const int cnt_signs = ceil(256.0 / cert_sz);            //кол-во подписей
const int cnt_vars = K * cnt_signs;                     //количество переменных для подписи



class UOV_center {
private:
    Matr Fs[K];
    Matr Gs[K];
    Matr A_1 = Matr(N, N);

    void gen_polinimial() {
        Matr A = Matr(N, N);
        Matr A_T = Matr(N, N);
        A.rand_matr();
        get_m_and_inverse_m(A, A_1);
        transpose_matr(A, A_T);

        for (int i = 0; i < K; ++i) {
            Fs[i].rand_matr();
            Fs[i].convert_to_upper_triang();
            Fs[i].null_right_bottom_corner(R);
        }

        Matr t_m(N, N);
        for (int i = 0; i < K; ++i) {
            mul_matr_matr(A, Fs[i], t_m);
            mul_matr_matr(t_m, A_T, Gs[i]);
            Gs[i].convert_to_upper_triang();
        }

        std::ofstream ofs_s("CA_secret.dat", std::ios::binary);
        //по-хорошему сертификат должен быть вшит в корневой центр сертификации изначально
        std::ofstream ofs_p("../../../CA_public.dat", std::ios::binary);
        if (!ofs_s || !ofs_s) {
            return;
        }

        for (size_t i = 0; i < K; ++i) {
            Fs[i].write_to_file(ofs_s);
        }
        for (size_t i = 0; i < K; ++i) {
            Gs[i].write_to_file(ofs_s);
            Gs[i].write_to_file(ofs_p);
        }
        A_1.write_to_file(ofs_s);

        ofs_s.close();
        ofs_p.close();
    }

    bool restore_data() {
        std::ifstream ifs("CA_secret.dat", std::ios::binary);
        if (!ifs) {
            return false;
        }

        try {
            for (size_t i = 0; i < K; ++i) {
                Fs[i].read_from_file(ifs);
            }
            for (size_t i = 0; i < K; ++i) {
                Gs[i].read_from_file(ifs);
            }
            A_1.read_from_file(ifs);

        }
        catch (...) {
            return false;
        }


        return true;
    }


public:
    UOV_center() {
        if (!restore_data()) {
            gen_polinimial();
        }
    }

    void sign_cert(const std::vector<uint8_t>& msg, std::vector<uint8_t>& cert) {
        int* m = new int[cnt_vars]{};
        cert.clear();
        cert.resize(N * cnt_signs);
        {

            std::vector<uint8_t> hash;
            SHA::sha256(msg, hash);
            //hash.size = 256

            mpz_class hash_n;
            mpz_class t;
            mpz_t result;
            mpz_init(result);
            mpz_import(result, hash.size(), -1, 1, 1, 0, hash.data());
            hash_n = mpz_class(result);
            mpz_clear(result);

            mpz_class n_one_bit;
            for (int i = 0; i < one_symb_sz; ++i) {
                mpz_setbit(n_one_bit.get_mpz_t(), i);
            }

            for (int i = 0; i < cnt_parts; ++i) {
                t = hash_n & n_one_bit;
                hash_n >>= one_symb_sz;
                m[i] = (int)t.get_ui();
            }
        }


        Matr H = Matr(K, N - R);
        int* betta = new int[R];
        int* free_coefs = new int[K];
        int* sol = new int[N - R];
        int* x_sol = new int[N];
        int* y_sol = new int[N];

        for (int iter = 0; iter < cnt_signs; ++iter) {
            do {
                for (int i = 0; i < N - R; ++i) {
                    sol[i] = 0;
                }
                rand_vector(betta, R);

                int free_coef = 0;
                for (int i = 0; i < K; ++i) {
                    convert_UOV_to_linear_polynomial(R, Fs[i], betta, H, i, free_coef);
                    free_coefs[i] = (m[iter*K + i] - free_coef + Q) % Q;
                }

            } while (!solve_equation(H, free_coefs, sol));

            for (int i = 0; i < R; ++i) {
                x_sol[i] = betta[i];
            }
            for (int i = R; i < N; ++i) {
                x_sol[i] = sol[i - R];
            }

            mul_vec_matr(x_sol, A_1, y_sol);


            for (int i = 0; i < N; ++i) {
                cert[iter*N + i] = y_sol[i];
            }

            bool check_res = true;
            int t1[N]{};
            for (int i = 0; i < K; ++i) {
                mul_vec_matr(x_sol, Fs[i], t1);
                check_res &= (mul_vect_vect(t1, x_sol, N) == m[iter*K + i]);
            }

            for (int i = 0; i < K; ++i) {
                mul_vec_matr(y_sol, Gs[i], t1);
                check_res &= (mul_vect_vect(t1, y_sol, N) == m[iter*K + i]);
            }
        }

        delete[] betta; delete[] free_coefs; delete[] sol; delete[] x_sol; delete[] y_sol; delete[] m;

        /*
            bool check_res = true;
            int t1[N]{};
            for (int i = 0; i < K; ++i) {
                mul_vec_matr(x_sol, Fs[i], t1);
                check_res &= (mul_vect_vect(t1, x_sol, N) == m[i]);
            }

            for (int i = 0; i < K; ++i) {
                mul_vec_matr(y_sol, Gs[i], t1);
                check_res &= (mul_vect_vect(t1, y_sol, N) == m[i]);
            }
            std::cout << "check: " << check_res << std::endl;
            */
    }
};


bool check_cert(std::vector<uint8_t>& msg, std::vector<uint8_t>& cert) {
    int* m = new int[cnt_vars]{};

    {
        std::vector<uint8_t> hash;
        SHA::sha256(msg, hash);
        //hash.size = 256


        mpz_class hash_n;
        mpz_class t;
        mpz_t result;
        mpz_init(result);
        mpz_import(result, hash.size(), -1, 1, 1, 0, hash.data());
        hash_n = mpz_class(result);
        mpz_clear(result);

        mpz_class n_one_bit;
        for (int i = 0; i < one_symb_sz; ++i) {
            mpz_setbit(n_one_bit.get_mpz_t(), i);
        }

        for (int i = 0; i < cnt_parts; ++i) {
            t = hash_n & n_one_bit;
            hash_n >>= one_symb_sz;
            m[i] = (int)t.get_ui();
        }
    }

    Matr Gs[K];

    std::ifstream ifs("CA_public.dat", std::ios::binary);
    for (size_t i = 0; i < K; ++i) {
        Gs[i].read_from_file(ifs);
    }
    ifs.close();


    int* y_sol = new int[N]{};
    int* t1 = new int[N]{};

    bool check_res = true;

    for (int iter = 0; iter < cnt_signs; ++iter) {
        for (int i = 0; i < N; ++i) {
            y_sol[i] = (int)cert[iter*N + i];
        }

        for (int i = 0; i < K; ++i) {
            mul_vec_matr(y_sol, Gs[i], t1);
            check_res &= (mul_vect_vect(t1, y_sol, N) == m[iter*K + i]);
        }
    }

    delete[] y_sol; delete[] t1; delete[] m;

    return check_res;
}

}


#undef Q
#undef N
#undef R
#undef K

#endif // UOV_H
