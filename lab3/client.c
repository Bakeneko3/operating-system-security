#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#define PORT       8083
#define CHAIN_LEN  1000

static unsigned char chain[CHAIN_LEN + 1][SHA256_DIGEST_LENGTH];

/* y_0 = H(seed), y_{i+1} = H(y_i) */
static void build_chain(const unsigned char *seed, size_t seed_len) {
    SHA256(seed, seed_len, chain[0]);
    for (int i = 0; i < CHAIN_LEN; i++) {
        SHA256(chain[i], SHA256_DIGEST_LENGTH, chain[i + 1]);
    }
}

static void to_hex(const unsigned char *in, char *out) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(out + 2 * i, "%02x", in[i]);
    out[SHA256_DIGEST_LENGTH * 2] = 0;
}

static int send_request(const char *msg, char *resp, size_t resp_len) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    send(fd, msg, strlen(msg), 0);

    memset(resp, 0, resp_len);
    recv(fd, resp, resp_len - 1, 0);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Использование: %s <логин> <seed>\n", argv[0]);
        return 1;
    }
    const char *login    = argv[1];
    const char *seed_str = argv[2];

    build_chain((const unsigned char*)seed_str, strlen(seed_str));

    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    char msg[256];
    char resp[64];

    /* Регистрация: отправляем y_N (последний элемент) */
    to_hex(chain[CHAIN_LEN], hex);
    snprintf(msg, sizeof(msg), "REG %s %s", login, hex);
    if (send_request(msg, resp, sizeof(resp)) < 0) return 1;
    printf("Регистрация: %s\n", resp);

    /* Аутентификация: y_{N-1}, y_{N-2}, ..., y_0 */
    for (int i = CHAIN_LEN - 1; i >= 0; i--) {
        to_hex(chain[i], hex);
        snprintf(msg, sizeof(msg), "AUTH %s %s", login, hex);
        if (send_request(msg, resp, sizeof(resp)) < 0) return 1;
        printf("Аутентификация #%d: %s\n", CHAIN_LEN - i, resp);
    }

    return 0;
}