#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define PORT 8084

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

int main(int argc, char **argv) {
    /* Секреты клиента s_i. Должны быть такими, что v_i = s_i^2 mod n.
       Здесь мы просто задаём их явно — в реальной системе они
       выдаются доверенным центром при регистрации. */
    uint64_t s[8] = {
        987654321ULL,
        876543210ULL,
        765432109ULL,
        654321098ULL,
        543210987ULL,
        432109876ULL,
        321098765ULL,
        210987654ULL
    };
    int K = 8;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    /* Получаем от сервера n и K */
    uint64_t n;
    int kk;
    if (recv_all(fd, &n, sizeof(n)) < 0) return 1;
    if (recv_all(fd, &kk, sizeof(kk)) < 0) return 1;
    K = kk;

    /* Приводим секреты по модулю n (на случай, если n меньше s_i) */
    for (int i = 0; i < K; i++) s[i] %= n;

    srand((unsigned)time(NULL) ^ getpid());

    for (int round = 0; round < 16; round++) {
        /* 1) r и x = r^2 mod n */
        uint64_t r = 2 + (uint64_t)rand() * rand() % (n - 3);
        uint64_t x = powmod(r, 2, n);
        send(fd, &x, sizeof(x), 0);

        /* 2) Принимаем битовый вектор e */
        unsigned char e[8];
        if (recv_all(fd, e, K) < 0) return 1;

        /* 3) y = r · ∏ s_i^{e_i} mod n */
        uint64_t y = r;
        for (int i = 0; i < K; i++)
            if (e[i]) y = mulmod(y, s[i], n);
        send(fd, &y, sizeof(y), 0);
    }

    char resp[5] = {0};
    recv(fd, resp, 4, 0);
    printf("Аутентификация: %s\n", resp);

    close(fd);
    return 0;
}