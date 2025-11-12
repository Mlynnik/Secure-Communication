#ifndef MATRIX_H
#define MATRIX_H

#include <stdlib.h>
#include <iostream>
#include <fstream>

#define Q 31
#define N 51
#define R 17
#define K 23

namespace UOV {
int mod_inv(int a, int m) {
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;

    a = a % m;
    while (a > 1) {
        q = a / m;
        t = m;

        m = a % m;
        a = t;
        t = x0;

        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
        x1 += m0;

    return x1;
}

void rand_vector(int* v, int sz) {
    for (int i = 0; i < sz; ++i) {
        v[i] = rand() % Q;
    }
}

int mul_vect_vect(int* v, int* v2, int sz) {
    int res = 0;
    for (int i = 0; i < sz; ++i) {
        res = (res + v[i] * v2[i]) % Q;
    }
    return res;
}


class Matr {
private:
    int** m;
    int rows, cols;

public:
    Matr(int _rows = N, int _cols = N) {
        rows = _rows; cols = _cols;
        m = new int* [rows];
        for (int i = 0; i < rows; ++i) {
            m[i] = new int[cols] {};
        }
    }

    void rand_matr() {
        for (int i = 0; i < rows; ++i) {
            for (int j = 0; j < cols; ++j) {
                m[i][j] = rand() % Q;
            }
        }
    }

    void refill(const Matr& m0) {
        for (int i = 0; i < rows; ++i) {
            for (int j = 0; j < cols; ++j) {
                m[i][j] = m0.m[i][j];
            }
        }
    }

    //находит обратную, если нужно изменяет исходную
    friend void get_m_and_inverse_m(const Matr& matrix, Matr& inverse) {
        while (!invert_by_mod(matrix, inverse)) {
            for (int i = 0; i < matrix.rows; ++i) {
                for (int j = 0; j < matrix.cols; ++j) {
                    matrix.m[i][j] = rand() % Q;
                }
            }
        }
    }

    void convert_to_upper_triang() {
        //матрица меняется
        for (int i = 0; i < rows; ++i) {
            for (int j = i + 1; j < cols; ++j) {
                m[i][j] = (m[i][j] + m[j][i]) % Q;
                m[j][i] = 0;
            }
        }
    }

    void null_right_bottom_corner(int r) {
        for (int i = r; i < rows; ++i) {
            for (int j = r; j < cols; ++j) {
                m[i][j] = 0;
            }
        }
    }

    //2 квадратных матрицы одного размера
    friend void mul_matr_matr(const Matr& m1, const Matr& m2, Matr& res) {
        for (int i = 0; i < m1.rows; ++i) {
            for (int j = 0; j < m1.cols; ++j) {
                res.m[i][j] = 0;
                for (int k = 0; k < m2.cols; ++k) {
                    res.m[i][j] = (res.m[i][j] + m1.m[i][k] * m2.m[k][j]) % Q;
                }
            }
        }
    }

    friend void mul_vec_matr(int* v, const Matr& m1, int* res) {
        for (int j = 0; j < m1.cols; ++j) {
            res[j] = 0;
            for (int i = 0; i < m1.rows; ++i) {
                res[j] = (res[j] + v[i] * m1.m[i][j]) % Q;
            }
        }
    }

    //квадратная матрица
    friend bool invert_by_mod(const Matr& matrix, Matr& inverse) {
        int n = matrix.rows;
        int** aug = new int* [n];
        for (int i = 0; i < n; ++i) {
            aug[i] = new int[2 * n];
        }

        for (int i = 0; i < n; ++i) {
            for (int j = 0; j < n; ++j) {
                aug[i][j] = matrix.m[i][j] % Q;
            }
            for (int j = n; j < 2 * n; ++j) {
                aug[i][j] = (i == j - n) ? 1 : 0;
            }
        }

        for (int i = 0; i < n; ++i) {
            int pivot = i;
            for (int row = i + 1; row < n; ++row) {
                if (aug[row][i] != 0) {
                    pivot = row;
                    break;
                }
            }
            if (aug[pivot][i] == 0) {
                for (int i = 0; i < n; ++i) {
                    delete[] aug[i];
                }
                delete[] aug;
                return false;
            }
            if (pivot != i) {
                std::swap(aug[i], aug[pivot]);
            }

            int inv = mod_inv(aug[i][i], Q);
            for (int j = 0; j < 2 * n; ++j) {
                aug[i][j] = (aug[i][j] * inv) % Q;
            }

            for (int row = 0; row < n; ++row) {
                if (row != i) {
                    int factor = aug[row][i];
                    for (int j = 0; j < 2 * n; ++j) {
                        aug[row][j] = ((aug[row][j] - factor * aug[i][j]) % Q + Q) % Q;
                    }
                }
            }
        }

        for (int i = 0; i < n; ++i) {
            for (int j = 0; j < n; ++j) {
                inverse.m[i][j] = aug[i][j + n];
            }
        }

        for (int i = 0; i < n; ++i) {
            delete[] aug[i];
        }
        delete[] aug;

        return true;
    }


    //квадратная матрица
    friend void convert_UOV_to_linear_polynomial(int r, const Matr& M, const int* betta,
                                                 Matr& H, int ind_zetta_R, int& free_coef) {
        int* zetta = new int[M.cols] {};
        int* zetta_R = H.m[ind_zetta_R];
        free_coef = 0;

        for (int j = 0; j < M.cols; ++j) {
            for (int i = 0; i < r; ++i) {
                zetta[j] = (zetta[j] + betta[i] * M.m[i][j]) % Q;
            }
        }

        for (int i = 0; i < r; ++i) {
            free_coef = (free_coef + zetta[i] * betta[i]) % Q;
        }

        for (int i = r; i < M.cols; ++i) {
            zetta_R[i - r] = zetta[i];
        }

        delete[] zetta;
    }

    friend bool solve_equation(const Matr& M, int* free_vars_in, int* solution) {
        Matr t_matr = Matr(M.rows, M.cols);
        t_matr.refill(M);


        int** matrix = t_matr.m;
        int n = M.rows;
        int m = M.cols;

        int* free_vars = new int[n];
        for (int i = 0; i < n; ++i) {
            free_vars[i] = free_vars_in[i];
        }

        int row = 0;

        for (int col = 0; col < m; ++col) {
            int pivot = -1;
            for (int i = row; i < n; ++i) {
                if (matrix[i][col] != 0) {
                    pivot = i;
                    break;
                }
            }
            if (pivot == -1) {
                continue;
            }

            if (pivot != row) {
                std::swap(matrix[pivot], matrix[row]);
                std::swap(free_vars[pivot], free_vars[row]);
            }


            int inv = mod_inv(matrix[row][col], Q);
            for (int j = col; j < m; ++j) {
                matrix[row][j] = (matrix[row][j] * inv) % Q;
            }
            free_vars[row] = (free_vars[row] * inv) % Q;

            for (int i = 0; i < n; ++i) {
                if (i != row && matrix[i][col] != 0) {
                    int factor = matrix[i][col];
                    for (int j = col; j < m; ++j) {
                        matrix[i][j] = ((matrix[i][j] - factor * matrix[row][j]) % Q + Q) % Q;
                    }
                    free_vars[i] = ((free_vars[i] - factor * free_vars[row]) % Q + Q) % Q;
                }
            }
            ++row;
        }

        for (int i = 0; i < n; ++i) {
            bool all_zero = true;
            for (int j = 0; j < m; ++j) {
                if (matrix[i][j] != 0) {
                    all_zero = false;
                    break;
                }
            }
            if (all_zero && free_vars[i] != 0) {
                delete[] free_vars;
                return false;
            }
        }

        for (int i = 0; i < n; ++i) {
            int leading_var = -1;
            for (int j = 0; j < m; ++j) {
                if (matrix[i][j] == 1) {
                    leading_var = j;
                    break;
                }
            }
            if (leading_var != -1) {
                solution[leading_var] = free_vars[i];
            }
        }
        delete[] free_vars;
        return true;
    }


    friend void transpose_matr(const Matr& m0, const Matr& mt) {
        for (int i = 0; i < m0.rows; ++i) {
            for (int j = 0; j < m0.cols; ++j) {
                mt.m[j][i] = m0.m[i][j];
            }
        }
    }

    void print() {
        for (int i = 0; i < rows; ++i) {
            for (int j = 0; j < cols; ++j) {
                std::cout << m[i][j] << ' ';
            }
            std::cout << std::endl;
        }
    }

    void write_to_file(std::ofstream& ofs) {
        for (size_t i = 0; i < rows; ++i) {
            ofs.write(reinterpret_cast<const char*>(m[i]), cols * sizeof(int));
        }
    }

    void read_from_file(std::ifstream& ifs) {
        for (size_t i = 0; i < rows; ++i) {
            ifs.read(reinterpret_cast<char*>(m[i]), cols * sizeof(int));
        }
    }

    ~Matr() {
        for (int i = 0; i < rows; ++i) {
            delete[] m[i];
        }
        delete[] m;
    }
};
}

#undef Q
#undef N
#undef R
#undef K

#endif // MATRIX_H
