#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include "AES.h"
#include "json.hpp"
#include "RSA.h"
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

void get_s(const RSA_server& srv, json& cert) {
    std::vector<uint8_t> pk_srv; pk_srv.reserve(256);
    mpzToBytes256(srv.get_field(), pk_srv);

    cert["id_srv"] = id_srv;
    cert["pk_srv"] = pk_srv;
    cert["id_ca"] = id_CA;
    cert["datetime"] = date_time;

    std::vector<uint8_t> serialized_data = serialize_json(cert);
}

void gen_iv(std::vector<uint8_t>& iv) {
    for (int i = 0; i < 16; ++i) {
        iv[i] = rand() % 256;
    }
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


void get_cert_from_ca(const RSA_server& srv) {
    // Подключение к server1
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        exit(1);
    }

    //сообщение для подписи центром сертификации
    std::vector<uint8_t> cert_clear_text;
    {
        json cert_clear_text_j;
        get_s(srv, cert_clear_text_j);
        cert_clear_text = serialize_json(cert_clear_text_j);

        std::ofstream ofs("cert_clear_text.dat", std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(cert_clear_text.data()), cert_clear_text.size() * sizeof(uint8_t));
        ofs.close();
    }

    if (!send_vector(sockfd, cert_clear_text)) {
        perror("write");
        exit(1);
    }

    std::vector<uint8_t> cert;
    if (!recv_vector(sockfd, cert)) {
        perror("read");
        exit(1);
    }

    {
        std::ofstream ofs("cert.dat", std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(cert.data()), cert.size() * sizeof(uint8_t));
        ofs.close();
    }

    close(sockfd);
    std::cout << "Server2 sent message to Server1 and disconnected" << std::endl;
}


int main() {
    srand(time(nullptr));
    RSA_server srv;

    {
        std::ifstream ifs_1("cert.dat");
        std::ifstream ifs_2("cert_clear_text.dat");

        if (!ifs_1.good() || !ifs_2.good()) {
            get_cert_from_ca(srv);
        }
    }


    std::vector<uint8_t> cert;
    std::vector<uint8_t> cert_clear_text;
    {
        std::ifstream ifs_1("cert.dat", std::ios::binary | std::ios::ate);
        std::ifstream ifs_2("cert_clear_text.dat", std::ios::binary | std::ios::ate);

        if (ifs_1) {
            std::streamsize f_sz = ifs_1.tellg();
            ifs_1.seekg(0, std::ios::beg);
            cert.resize(f_sz);
            ifs_1.read(reinterpret_cast<char*>(cert.data()), f_sz);
        }
        if (ifs_2) {
            std::streamsize f_sz = ifs_2.tellg();
            ifs_2.seekg(0, std::ios::beg);
            cert_clear_text.resize(f_sz);
            ifs_2.read(reinterpret_cast<char*>(cert_clear_text.data()), f_sz);
        }
    }



    // Теперь сервер2 слушает клиента
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in listen_addr;
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(12346);

    if (bind(listen_fd, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        exit(1);
    }

    listen(listen_fd, 5);
    std::cout << "Server2 listening for client on port 12346" << std::endl;

    struct sockaddr_in client_addr;
    socklen_t clilen = sizeof(client_addr);
    int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &clilen);
    if (client_fd < 0) {
        perror("accept");
        close(listen_fd);
        exit(1);
    }

    std::cout << "Server2 accepted connection from client" << std::endl;

    // Получение сообщения от клиента
    mpz_class alpha_mpz;
    {
        std::vector<uint8_t> alpha;
        if (!recv_vector(client_fd, alpha)) {
            perror("write");
            close(listen_fd);
            exit(1);
        }
        bytesToMpz256(alpha, alpha_mpz);
    }

    DiffieHellman user2(alpha_mpz);
    std::vector<uint8_t> betta; mpzToBytes256(user2.get_public_key(), betta);
    std::vector<uint8_t> betta_sign; srv.sign_msg(user2.get_public_key(), betta_sign);

    //общий ключ обрезаем до последних 256 бит, наиболее значимый бит всегда единица
    std::vector<uint8_t> common_key; common_key.reserve(256);
    {
        mpz_class common_key_mpz;
        user2.create_common_key(alpha_mpz);
        mpz_class one_256;
        for (int i = 0; i < 256; ++i) {
            mpz_setbit(one_256.get_mpz_t(), i);
        }
        common_key_mpz = user2.get_common_key() & one_256;
        mpz_setbit(common_key_mpz.get_mpz_t(), 255);
        mpzToBytes256(common_key_mpz, common_key);
    }

    std::vector<uint8_t> msg_to_enc;
    {
        json msg_to_enc_json;
        msg_to_enc_json["sign"] = betta_sign;
        msg_to_enc_json["s"] = cert_clear_text;
        msg_to_enc_json["cert"] = cert;
        msg_to_enc = serialize_json(msg_to_enc_json);
    }

    std::vector<uint8_t> iv(16, 0);
    for (int i = 0; i < 16; ++i) {
        iv[i] = rand() % 256;
    }

    std::vector<uint8_t> enc_msg;

    AES::encrypt(msg_to_enc, common_key, iv, enc_msg);

    std::vector<uint8_t> final_msg;
    {
        json final_msg_json;
        final_msg_json["betta"] = betta;
        final_msg_json["iv"] = iv;
        final_msg_json["enc_msg"] = enc_msg;
        final_msg = serialize_json(final_msg_json);
    }



    if (!send_vector(client_fd, final_msg)) {
        perror("write");
        close(listen_fd);
        exit(1);
    }

    std::vector<uint8_t> msg;
    std::vector<uint8_t> dec_msg;
    std::string line;
    int sz_msg;
    do {
        line.clear();
        if (!recv_vector(client_fd, msg)) {
            perror("write");
            close(client_fd);
            exit(0);
        }

        sz_msg = msg.size() - 16;
        if (sz_msg < 16) {
            close(client_fd);
            exit(1);
        }
        for (int i = 0; i < 16; ++i) {
            iv[i] = msg[sz_msg + i];
        }
        msg.resize(sz_msg);
        AES::decrypt(msg, common_key, iv, dec_msg);

        line.clear();
        line = std::string(dec_msg.begin(), dec_msg.end());
        std::cout << "answer:    " << line << std::endl;

        gen_iv(iv);
        std::cout << "enter msg: ";
        std::getline(std::cin, line);
        if (line == "q") {
            std::cout << "disconnecting..." << std::endl;
            close(client_fd);
            return 0;
        }
        msg = std::vector<uint8_t>(line.begin(), line.end());
        AES::encrypt(msg, common_key, iv, enc_msg);
        copy(iv.begin(), iv.end(), back_inserter(enc_msg));

        if (!send_vector(client_fd, enc_msg)) {
            perror("write");
            close(client_fd);
            exit(1);
        }

    } while (true);


    close(client_fd);
    close(listen_fd);

    return 0;
}
