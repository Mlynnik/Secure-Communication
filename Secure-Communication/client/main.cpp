#include "AES.h"
#include "RSA.h"
#include "UOV.h"
#include "json.hpp"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include "DiffieHellman.h"


using json = nlohmann::json;

const std::string id_CA = "myca.net";
const std::string id_srv = "myserver.net";
const std::string date_time = "10.10.2026";

std::vector<uint8_t> serialize_json(const json& j) {
    std::string s = j.dump();
    return std::vector<uint8_t>(s.begin(), s.end());
}

json deserialize_json(const std::vector<uint8_t>& data) {
    std::string s(data.begin(), data.end());
    json res;
    try {
        res = json::parse(s);
    } catch(...) {
        res.clear();
    }
    return res;
}

bool recv_vector(int sockfd, std::vector<uint8_t>& data) {
    uint32_t size_net;
    ssize_t n = recv(sockfd, &size_net, sizeof(size_net), MSG_WAITALL);
    if (n != sizeof(size_net)) {
        return false;
    }
    uint32_t size = ntohl(size_net);

    data.resize(size);
    size_t total_received = 0;
    while (total_received < size) {
        ssize_t n = recv(sockfd, data.data() + total_received, size - total_received, 0);
        if (n <= 0) {
            return false;
        }
        total_received += n;
    }
    return true;
}

bool send_vector(int sockfd, const std::vector<uint8_t>& data) {
    uint32_t size = data.size();
    uint32_t size_net = htonl(size);

    ssize_t sent_bytes = send(sockfd, &size_net, sizeof(size_net), 0);
    if (sent_bytes != sizeof(size_net)) {
        return false;
    }

    size_t total_sent = 0;
    while (total_sent < size) {
        ssize_t n = send(sockfd, data.data() + total_sent, size - total_sent, 0);
        if (n <= 0) {
            return false;
        }
        total_sent += n;
    }

    return true;
}


void gen_iv(std::vector<uint8_t>& iv) {
    for (int i = 0; i < 16; ++i) {
        iv[i] = rand() % 256;
    }
}


void establish_connection() {

}


int main() {
    srand(time(nullptr));
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(12346);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }


    DiffieHellman user1;
    std::vector<uint8_t> alpha; alpha.reserve(256); mpzToBytes256(user1.get_public_key(), alpha);
    if (!send_vector(sockfd, alpha)) {
        perror("write");
        exit(1);
        close(sockfd);
    }



    std::vector<uint8_t> final_msg;
    if (!recv_vector(sockfd, final_msg)) {
        perror("write");
        exit(1);
        close(sockfd);
    }


    mpz_class betta;
    std::vector<uint8_t> common_key; common_key.reserve(256);
    std::vector<uint8_t> dec_msg_v;
    {
        json final_msg_json = deserialize_json(final_msg);
        if (final_msg_json.is_null()) {
            std::cout << "error in decoding json" << std::endl;
            close(sockfd);
            exit(1);
        }
        std::vector<uint8_t> betta_v = final_msg_json["betta"];
        bytesToMpz256(betta_v, betta);
        user1.create_common_key(betta);

        mpz_class common_key_mpz;
        {
            mpz_class one_256;
            for (int i = 0; i < 256; ++i) {
                mpz_setbit(one_256.get_mpz_t(), i);
            }
            common_key_mpz = user1.get_common_key() & one_256;
            mpz_setbit(common_key_mpz.get_mpz_t(), 255);
            mpzToBytes256(common_key_mpz, common_key);
        }

        std::vector<uint8_t> iv = final_msg_json["iv"];
        std::vector<uint8_t> enc_msg = final_msg_json["enc_msg"];
        AES::decrypt(enc_msg, common_key, iv, dec_msg_v);
    }

    //check sign and cert
    bool is_sign = false;
    {
        mpz_class pk_srv_mpz;
        json dec_msg_json = deserialize_json(dec_msg_v);
        if (dec_msg_json.is_null()) {
            std::cout << "error in decoding json" << std::endl;
            close(sockfd);
            exit(1);
        }
        {
            std::vector<uint8_t> open_cert_v = dec_msg_json["s"];
            std::vector<uint8_t> cert_v = dec_msg_json["cert"];

            is_sign = UOV::check_cert(open_cert_v, cert_v);
            if (!is_sign) {
                std::cout << "not correct certificate" << std::endl;
                exit(1);
                close(sockfd);
            }

            json cert = deserialize_json(open_cert_v);
            if (cert.is_null()) {
                std::cout << "error in decoding json" << std::endl;
                exit(1);
            }
            if (cert["id_srv"] != id_srv || cert["id_ca"] != id_CA) {
                std::cout << "not correct certificate" << std::endl;
                exit(1);
                close(sockfd);
            }

            std::vector<uint8_t> pk_srv = cert["pk_srv"];
            bytesToMpz256(pk_srv, pk_srv_mpz);
        }


        std::vector<uint8_t> sign_betta = dec_msg_json["sign"];
        is_sign = RSA_client::check_sign(sign_betta, betta, pk_srv_mpz);
        if (!is_sign) {
            std::cout << "not correct sign" << std::endl;
            close(sockfd);
            exit(1);
        }
    }

    std::cout << "connection established!" << std::endl;


    std::vector<uint8_t> msg;
    std::vector<uint8_t> enc_msg;
    std::vector<uint8_t> dec_msg;
    std::string line;
    std::vector<uint8_t> iv(16, 0);
    int sz_msg;
    do {
        line.clear();
        gen_iv(iv);

        std::cout << "enter msg: ";
        std::getline(std::cin, line);
        if (line == "q") {
            std::cout << "disconnecting..." << std::endl;
            close(sockfd);
            return 0;
        }
        msg = std::vector<uint8_t>(line.begin(), line.end());
        AES::encrypt(msg, common_key, iv, enc_msg);
        copy(iv.begin(), iv.end(), back_inserter(enc_msg));

        if (!send_vector(sockfd, enc_msg)) {
            perror("write");
            close(sockfd);
            exit(1);
        }

        if (!recv_vector(sockfd, msg)) {
            perror("write");
            close(sockfd);
            exit(0);
        }

        sz_msg = enc_msg.size() - 16;
        if (sz_msg < 16) {
            close(sockfd);
            exit(1);
        }
        for (int i = 0; i < 16; ++i) {
            iv[i] = msg[sz_msg + i];
        }
        msg.resize(sz_msg);
        AES::decrypt(msg, common_key, iv, dec_msg);

        line.clear();
        line = std::string(dec_msg.begin(), dec_msg.end());
        std::cout << "answer:    "<< line << std::endl;

    } while (true);

    close(sockfd);
    return 0;
}
