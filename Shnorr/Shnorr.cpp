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


//������� ��������� �������� �����
Integer get_prime(unsigned int bytes) {
    AutoSeededRandomPool prng;
    Integer x;
    do {
        x.Randomize(prng, bytes);
    } while (!IsPrime(x));

    return x;
}

//������� �������� ����� �� ��������
Integer simple(const Integer n) {
    for (int i = 2; i <= n.SquareRoot(); i++)
        if ((n % i) == 0)
            return 0;
    return 1;
}

// ����� ���������� �����
class Trust_Center_T {
private:
    Integer q;
    Integer p;
    Integer t = 1;
    Integer g;

    byte* output;

public:
    //������� ��������� �������� ����� p
    Integer get_p() {
        cout << "���� 1." << endl;
        p = get_prime(BLOCKSIZE);
        cout << "����� �������. p = " << p << endl;
        return p;
    }
    //������� ��������� �������� ����� q, ��� q|(p-1)
    Integer get_q() {
        q = (p - 1) / 2;
        cout << "����� �������. q = " << q << endl;
        return p;
    }
    //������� ��������� t, ��� ��� ����� ���������, ���������� ���������
    Integer get_t() {
        Integer a;

        /*while (true) {
            a = a_exp_b_mod_c(2, t, q);
            if (a >= q) {
                cout << "����� �������. ������ �������� ������������ t = " << t << endl;
                return (t - 1);
            }
            t += 1;
        }*/
        t = 5;
        cout << "����� �������. ������ �������� ������������ t = " << t << endl;
        return t;
    }

    //������� ��������� g
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
        cout << "����� �������. ������ ������� g = " << g << endl;
        return g;   
    }

    //��������� ���������� p, q, g, t
    tuple<Integer, Integer, Integer, Integer>parametrs() {
        return make_tuple(p, q, g, t);
    }

    //������� ��������� �����������
    tuple<Integer, Integer, string>certA(Integer V, Integer IA_P) {
        cout << "����� �������. �������� �������� ���� V = " << V << " � IA_P = " << IA_P << endl;
        stringstream ss;
        ss << hex << V + IA_P;
        //cout << hex << V + IA_P << endl;
        string V_and_IA = ss.str();
        cout << "����� �������. ���������� ������� = " << V_and_IA << endl;
        //V_and_IA = V + IA_P;
        return make_tuple(V, IA_P, V_and_IA);
    }
};

// ����� �����������
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
    const Integer  equiv = Integer::Zero(); //�������, ������������ 0
    const Integer mod = Integer::One(); //�������, ������������ 1

public:
    // ������� ��������� IA_V Check
    Integer get_IA_V() {
        IA_V = get_prime(BLOCKSIZE);
        cout << "Check. ������������� IA_V ��� ������������. IA_V = " << IA_V << endl;
        return IA_V;
    }

    //������� �������� x, ������� ������������ User
    Integer check_x(Trust_Center_T& T, Integer x, tuple<Integer, Integer, string> certA_1, Integer status) {
        tie(p, q, g, t) = T.parametrs();

        cout << "Check. ������� certA �� �������������� ������: " << endl;

        tie(vP, iap, certAA) = certA_1;

        tie(vP1, iap1, certAA1) = T.certA(vP, iap);

        cout << "Check. ������� x = " << x << endl;
        get_x = x;
        //���������� �������
        if (status == 1) {
            cout << "Check. �������� �������: " << certAA1 << " ? " << certAA << endl;
            if (certAA1 == certAA) {
                cout << "Check. �������� ������� ����������� ������ ������ �������" << endl;
                e = Integer::Integer(rng, 1, a_exp_b_mod_c(2, t, q), rnType, equiv, mod); // ����� ���������� ����� �� ���������
                cout << "Check. ������������� e = " << e << endl;
                cout << "Check. �������� e..." << endl;
                return e;
            }
            else {
                cout << "Check. �������� ������� ����������� ������ ������ ���������" << endl;
                return 0;
            }
        } //������������ �������
        else if (status == 0) {
            string certA_error = "hiuop"; //���������������� �������� �������
            string hash = "";
            
            StringSource ssk(certA_error, true, new HexEncoder(new StringSink(hash))); // ����������� �������
            cout << "Check. �������� �������: " << hash << " ? " << certAA << endl;
            if (hash == certAA) {
                cout << "Check. �������� ������� ����������� ������ ������ �������" << endl;
                e = Integer::Integer(rng, 1, a_exp_b_mod_c(2, t, q), rnType, equiv, mod);// ����� ���������� ����� �� ���������
                cout << "Check. ������������� e = " << e << endl;
                cout << "Check. �������� e..." << endl;
                return e;
            }
            else {
                cout << "Check. �������� ������� ����������� ������ ������ ���������" << endl;
                return 0;
            }
        }
        
    }

    // ������� �������� y, ������� ������������ User
    Integer check_y(Trust_Center_T& T, Integer y, Integer V) {
        tie(p, q, g, t) = T.parametrs();
        Integer z;
        cout << "Check. ������� � = " << y << endl;
        cout << "Check. ��������� z..." << endl;
        z = a_exp_b_mod_c(EuclideanDomainOf<Integer>().Exponentiate(g, y) * EuclideanDomainOf<Integer>().Exponentiate(V, e), 1, p);
        cout << "Check. ������������� z = " << z << endl;
        cout << "Check. ��������: z = " << z <<" ?? "<<" x = "<< get_x << endl;
        if (z == get_x) {
            cout << "Check. �������������� �������" << endl;
            return 1;
        }
        else {
            cout << "Check. �������������� ���������" << endl;
            return 0;
        }
    }
};

// ����� ������������
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
    // ������� ��������� IA_P User
    Integer get_IA_P() {
        cout << "���� 2." << endl;
        IA_P = get_prime(BLOCKSIZE);
        cout << "User. ������������� IA_P ��� ������������. IA_P = " << IA_P << endl;
        return IA_P;
    }
    // ������� ��������� ��������� ����� A � ��������� ����� V
    tuple<Integer, Integer, string> get_A_V(Trust_Center_T& T) {
        tie(p, q, g, t) = T.parametrs();
        Integer k;
        A = Integer::Integer(rng, 1, q - 1, rnType, equiv, mod);
        cout << "User. ������������ �������� ���� A = " << A << endl;
        V = a_exp_b_mod_c(g, (q - A), p);
        cout << "User. ������������ �������� ���� V = " << V << endl;
        cout << "User. �������� V � IA_P ����������� ������..." << endl;
        tie(vP, iap, certA) = T.certA(V, IA_P);
        cout << "User. �������� �� ����������� ������ certA" << endl;
        cout << "V = " << V << " IA_P = " << iap << " certA = " << certA << endl;

        certA_1 = make_tuple(vP, iap, certA);

        return certA_1;
    }

    // ������� �� ��������� r, x, 
    Integer get_r(Trust_Center_T& T, Check_V& Vv, Integer status) {
        cout << "���� 3." << endl;
        tie(p, q, g, t) = T.parametrs();
        r = Integer::Integer(rng, 1, q, rnType, equiv, mod); // ��������� r
        cout << "User. ������������ r = " << r << endl;
        x = a_exp_b_mod_c(g, r, p); // ���������� x
        cout << "User. �������� x = " << x << endl;
        cout << "User. �������� ������������ x ..." << endl;

        Integer get_e, y, check_y_P;
        get_e = Vv.check_x(T, x, certA_1, status); // �������� � �� �������� ������������
        if (get_e != 0) {
            cout << "User. �������� e = " << get_e << endl;
            cout << "User. �������� 1 < e < 2^t" << endl;
            if (1 < get_e < a_exp_b_mod_c(2, t, q)) {
                cout << "User. ��������� �..." << endl;
                y = a_exp_b_mod_c(A * get_e + r, 1, q);
                cout << "User. �������� � = " << y << endl;
                cout << "User. �������� ������������ � ..." << endl;
                check_y_P = Vv.check_y(T, y, V);
                if (check_y_P == 1) {
                    cout << "User. �������" << endl;
                    return 1;
                }else if (check_y_P == 0) {
                    cout << "User. ������" << endl;
                return 0;
                }
            }else {
                cout << "User. � �� ����� � ���������: 1 < e < 2^t" << endl;
                return 0;
            }
        }
        else if (get_e == 0) {
            cout << "User. ������ � �������� �������." << endl;
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

    //���������� ������
    //Integer status = 1;
    //���������� ������
    Integer status = 0;

    P.get_r(T, V, status);


    system("pause");
    return 0;
}

