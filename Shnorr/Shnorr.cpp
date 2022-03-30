#include <iostream>
#include <string> 
#include <cmath>
#include <tuple>
#include <vector>

#include "../cryptopp860/cryptlib.h"
#include "../cryptopp860/modes.h"
#include "../cryptopp860/filters.h"
#include "../cryptopp860/osrng.h" // PNG AutoSeededRandomPool
#include "../cryptopp860/integer.h"
#include "../cryptopp860/nbtheory.h"
#include "../cryptopp860/hex.h"
#include "../cryptopp860/algebra.h"


using namespace CryptoPP;
using namespace std;

const unsigned int BLOCKSIZE = 16;


//функция генерации простого числа
Integer get_prime(unsigned int bytes) {
    AutoSeededRandomPool prng;
    Integer x;
    do {
        x.Randomize(prng, bytes);
    } while (!IsPrime(x));

    return x;
}

//функция проверки числа на простоту
Integer simple(const Integer n) {
    for (int i = 2; i <= n.SquareRoot(); i++)
        if ((n % i) == 0)
            return 0;
    return 1;
}

// класс Доверенный центр
class Trust_Center_T {
private:
    Integer q;
    Integer p;
    Integer t = 1;
    Integer g;

    byte* output;

public:
    //Функция генерации простого числа p
    Integer get_p() {
        cout << "Этап 1." << endl;
        p = get_prime(BLOCKSIZE);
        cout << "Центр доверия. p = " << p << endl;
        return p;
    }
    //Функция генерации простого числа q, где q|(p-1)
    Integer get_q() {
        q = (p - 1) / 2;
        cout << "Центр доверия. q = " << q << endl;
        return p;
    }
    //Функция генерации t, так как долго вычисляет, подставила константу
    Integer get_t() {
        Integer a;

        /*while (true) {
            a = a_exp_b_mod_c(2, t, q);
            if (a >= q) {
                cout << "Центр доверия. Выбран параметр безопасности t = " << t << endl;
                return (t - 1);
            }
            t += 1;
        }*/
        t = 5;
        cout << "Центр доверия. Выбран параметр безопасности t = " << t << endl;
        return t;
    }

    //Функция генерации g
    Integer get_g() {
        vector<Integer> arr_g;
        for (Integer k = 1; k < p - 1; k++) {
            if (a_exp_b_mod_c(k, q, p) == 1) {
                arr_g.push_back(k);
            }
        }
        /*
        for (vector<Integer>::iterator it = arr_g.begin(); it != arr_g.end(); ++it)
            cout << *it << endl;
        */
        g = *max_element(arr_g.begin(), arr_g.end());
        cout << "Центр доверия. Выбран элемент g = " << g << endl;
        return g;   
    }

    //Получение параметров p, q, g, t
    tuple<Integer, Integer, Integer, Integer>parametrs() {
        return make_tuple(p, q, g, t);
    }

    //Функция получения сертификата
    tuple<Integer, Integer, string>certA(Integer V, Integer IA_P) {
        cout << "Центр доверия. Получает открытый ключ V = " << V << " и IA_P = " << IA_P << endl;
        stringstream ss;
        ss << hex << V + IA_P;
        //cout << hex << V + IA_P << endl;
        string V_and_IA = ss.str();
        cout << "Центр доверия. Уникальная подпись = " << V_and_IA << endl;
        //V_and_IA = V + IA_P;
        return make_tuple(V, IA_P, V_and_IA);
    }
};

// класс Проверяющий
class Check_V {
private:
    Integer IA_V;
    Integer p, q, g, t;
    Integer e, get_x;
    Integer vP, iap;
    string certAA;
    Integer vP1, iap1;
    string certAA1;

    AutoSeededRandomPool rng;
    enum Integer::RandomNumberType rnType = Integer::ANY;
    const Integer  equiv = Integer::Zero(); //функция, возвращающая 0
    const Integer mod = Integer::One(); //функция, возвращающая 1

public:
    // Функция генерации IA_V Check
    Integer get_IA_V() {
        IA_V = get_prime(BLOCKSIZE);
        cout << "Check. Сгенерировано IA_V для проверяющего. IA_V = " << IA_V << endl;
        return IA_V;
    }

    //функция проверки x, которое сгенерировал User
    Integer check_x(Trust_Center_T& T, Integer x, tuple<Integer, Integer, string> certA_1, Integer status) {
        tie(p, q, g, t) = T.parametrs();

        cout << "Check. Получен certA от Доверительного центра: " << endl;

        tie(vP, iap, certAA) = certA_1;

        tie(vP1, iap1, certAA1) = T.certA(vP, iap);

        cout << "Check. Получен x = " << x << endl;
        get_x = x;
        //корректный вариант
        if (status == 1) {
            cout << "Check. Проверка подписи: " << certAA1 << " ? " << certAA << endl;
            if (certAA1 == certAA) {
                cout << "Check. Проверка подписи доверенного центра прошла УСПЕШНО" << endl;
                e = Integer::Integer(rng, 1, a_exp_b_mod_c(2, t, q), rnType, equiv, mod); // выбор случайного числа из диапазона
                cout << "Check. Сгенерировано e = " << e << endl;
                cout << "Check. Отправка e..." << endl;
                return e;
            }
            else {
                cout << "Check. Проверка подписи доверенного центра прошла НЕУСПЕШНО" << endl;
                return 0;
            }
        } //некорректный вариант
        else if (status == 0) {
            string certA_error = "hiuop"; //предопределенное значение подписи
            string hash = "";
            
            StringSource ssk(certA_error, true, new HexEncoder(new StringSink(hash))); // хеширование подписи
            cout << "Check. Проверка подписи: " << hash << " ? " << certAA << endl;
            if (hash == certAA) {
                cout << "Check. Проверка подписи доверенного центра прошла УСПЕШНО" << endl;
                e = Integer::Integer(rng, 1, a_exp_b_mod_c(2, t, q), rnType, equiv, mod);// выбор случайного числа из диапазона
                cout << "Check. Сгенерировано e = " << e << endl;
                cout << "Check. Отправка e..." << endl;
                return e;
            }
            else {
                cout << "Check. Проверка подписи доверенного центра прошла НЕУСПЕШНО" << endl;
                return 0;
            }
        }
        
    }

    // функция проверки y, который сгенерировал User
    Integer check_y(Trust_Center_T& T, Integer y, Integer V) {
        tie(p, q, g, t) = T.parametrs();
        Integer z;
        cout << "Check. Получен у = " << y << endl;
        cout << "Check. Генерация z..." << endl;
        z = a_exp_b_mod_c(EuclideanDomainOf<Integer>().Exponentiate(g, y) * EuclideanDomainOf<Integer>().Exponentiate(V, e), 1, p);
        cout << "Check. Сгенерировано z = " << z << endl;
        cout << "Check. Проверка: z = " << z <<" ?? "<<" x = "<< get_x << endl;
        if (z == get_x) {
            cout << "Check. Доказательство принято" << endl;
            return 1;
        }
        else {
            cout << "Check. Доказательство непринято" << endl;
            return 0;
        }
    }
};

// класс Пользователь
class User_P {
private:
    Integer IA_P;
    Integer A;
    Integer p, q, t, g;
    Integer V, r, x;
    Integer vP, iap;
    string certA;
    tuple<Integer, Integer, string> certA_1;

    AutoSeededRandomPool rng;
    enum Integer::RandomNumberType rnType = Integer::ANY;
    const Integer  equiv = Integer::Zero();
    const Integer mod = Integer::One();

public:
    // Функция получения IA_P User
    Integer get_IA_P() {
        cout << "Этап 2." << endl;
        IA_P = get_prime(BLOCKSIZE);
        cout << "User. Сгенерировано IA_P для пользователя. IA_P = " << IA_P << endl;
        return IA_P;
    }
    // Функция генерации закрытого ключа A и открытого ключа V
    tuple<Integer, Integer, string> get_A_V(Trust_Center_T& T) {
        tie(p, q, g, t) = T.parametrs();
        Integer k;
        A = Integer::Integer(rng, 1, q - 1, rnType, equiv, mod);
        cout << "User. Сгенерирован закрытый ключ A = " << A << endl;
        V = a_exp_b_mod_c(g, (q - A), p);
        cout << "User. Сгенерирован открытый ключ V = " << V << endl;
        cout << "User. Отправка V и IA_P доверенному центру..." << endl;
        tie(vP, iap, certA) = T.certA(V, IA_P);
        cout << "User. Получено от Доверенного центра certA" << endl;
        cout << "V = " << V << " IA_P = " << iap << " certA = " << certA << endl;

        certA_1 = make_tuple(vP, iap, certA);

        return certA_1;
    }

    // функцию по генерации r, x, 
    Integer get_r(Trust_Center_T& T, Check_V& Vv, Integer status) {
        cout << "Этап 3." << endl;
        tie(p, q, g, t) = T.parametrs();
        r = Integer::Integer(rng, 1, q, rnType, equiv, mod); // генерауия r
        cout << "User. Сгенерирован r = " << r << endl;
        x = a_exp_b_mod_c(g, r, p); // вычисление x
        cout << "User. Вычислен x = " << x << endl;
        cout << "User. Отправка проверяющему x ..." << endl;

        Integer get_e, y, check_y_P;
        get_e = Vv.check_x(T, x, certA_1, status); // отправка х на проверку проверяющему
        if (get_e != 0) {
            cout << "User. Получено e = " << get_e << endl;
            cout << "User. Проверка 1 < e < 2^t" << endl;
            if (1 < get_e < a_exp_b_mod_c(2, t, q)) {
                cout << "User. Генерация у..." << endl;
                y = a_exp_b_mod_c(A * get_e + r, 1, q);
                cout << "User. Получено у = " << y << endl;
                cout << "User. Отправка проверяющему у ..." << endl;
                check_y_P = Vv.check_y(T, y, V);
                if (check_y_P == 1) {
                    cout << "User. Принято" << endl;
                    return 1;
                }else if (check_y_P == 0) {
                    cout << "User. Провал" << endl;
                return 0;
                }
            }else {
                cout << "User. е не лежит в интервале: 1 < e < 2^t" << endl;
                return 0;
            }
        }
        else if (get_e == 0) {
            cout << "User. Ошибка в проверке подписи." << endl;
            return 0;
        } 
    }
};


int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "rus");

    Trust_Center_T T;
    User_P P;
    Check_V V;

    Integer p, q, g, t;

    T.get_p();
    T.get_q();
    T.get_g();
    T.get_t();

    //tie(p, q, g, t) = T.parametrs();

    P.get_IA_P();
    V.get_IA_V();


    P.get_A_V(T);

    //корректные данные
    //Integer status = 1;
    //корректные данные
    Integer status = 0;

    P.get_r(T, V, status);


    system("pause");
    return 0;
}

