#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <vector>
#include "UOV.h"

bool recv_vector(int sockfd, std::vector<uint8_t>& data) {
    uint32_t size_net;
    ssize_t n = recv(sockfd, &size_net, sizeof(size_net), MSG_WAITALL);
    if (n != sizeof(size_net)) {
        return -1;
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

int main() {
    srand(time(nullptr));
    int sockfd, newsockfd;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(12345);

    if (bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(1);
    }

    listen(sockfd, 5);
    std::cout << "Server1 listening on port 12345" << std::endl;

    //сейчас центр сертификации отключается после 1 запроса
    //но можно сделать бесконечный цикл
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr*)&cli_addr, &clilen);
    if (newsockfd < 0) {
        perror("accept");
        close(sockfd);
        exit(1);
    }

    std::cout << "Server1 accepted connection" << std::endl;

    std::vector<uint8_t> buffer;
    recv_vector(newsockfd, buffer);

    std::vector<uint8_t> cert;
    UOV::UOV_center ca;
    ca.sign_cert(buffer, cert);

    send_vector(newsockfd, cert);

    close(newsockfd);
    close(sockfd);
    std::cout << "Server1 disconnected" << std::endl;

    return 0;
}
