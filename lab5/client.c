#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#define PORT 8085

static const uint64_t P = 0xFFFFFFFFFFFFFFC5ULL;
static const uint64_t G = 2;

static uint64_t mulmod(uint64_t a, uint64_t b, uint64_t m) {
    return (uint64_t)((__uint128_t)a * b % m);
}
static uint64_t powmod(uint64_t a, uint64_t e, uint64_t m) {
    uint64_t r = 1; a %= m;
    while (e) {
        if (e & 1) r = mulmod(r, a, m);
        a = mulmod(a, a, m);
        e >>= 1;
    }
    return r;
}
static int recv_all(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, (char*)buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}
static void xor_crypt(unsigned char *data, size_t n,
                      const unsigned char *key, size_t klen) {
    for (size_t i = 0; i < n; i++) data[i] ^= key[i % klen];
}

int main(int argc, char **argv) {
    const char *msg = (argc > 1) ? argv[1] : "Привет от клиента!";

    /* 1. Случайный a, считаем A = g^a mod p */
    srand((unsigned)time(NULL) ^ getpid());
    uint64_t a = 2 + (uint64_t)rand() * rand() % (P - 3);
    uint64_t A = powmod(G, a, P);

    /* 2. Подключаемся */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    /* 3. Отправляем A, получаем B */
    send(fd, &A, sizeof(A), 0);
    uint64_t B;
    if (recv_all(fd, &B, sizeof(B)) < 0) return 1;

    /* 4. Считаем K = B^a mod p */
    uint64_t K = powmod(B, a, P);

    /* 5. KDF */
    unsigned char key[32];
    SHA256((unsigned char*)&K, sizeof(K), key);

    /* 6. Шифруем сообщение и шлём */
    size_t msg_len = strlen(msg);
    unsigned char buf[4096];
    memcpy(buf, msg, msg_len);
    xor_crypt(buf, msg_len, key, sizeof(key));

    uint32_t len32 = (uint32_t)msg_len;
    send(fd, &len32, sizeof(len32), 0);
    send(fd, buf, msg_len, 0);

    /* 7. Читаем подтверждение */
    char resp[8] = {0};
    recv(fd, resp, 7, 0);
    printf("Сервер ответил: %s\n", resp);

    close(fd);
    return 0;
}