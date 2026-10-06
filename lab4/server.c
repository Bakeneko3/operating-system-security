#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define PORT    8084
#define K       8
#define ROUNDS  16

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

int main(void) {
    const uint64_t n = 1000003ULL * 1000033ULL;

    /* !!! Те же самые s_i, что у клиента !!!
       (в реальности секреты хранит только клиент, а v_i сервер
        получает из доверенного центра — здесь мы их "эмулируем") */
    uint64_t s[K] = {
        987654321ULL, 876543210ULL, 765432109ULL, 654321098ULL,
        543210987ULL, 432109876ULL, 321098765ULL, 210987654ULL
    };

    /* v_i = s_i^2 mod n — вот это и есть настоящий публичный ключ */
    uint64_t v[K];
    for (int i = 0; i < K; i++) {
        s[i] %= n;
        v[i] = powmod(s[i], 2, n);
    }

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sfd, (struct sockaddr*)&addr, sizeof(addr));
    listen(sfd, 4);

    printf("Сервер Фиата—Шамира на порту %d\n", PORT);
    printf("n = %llu, раундов = %d, секретов = %d\n",
           (unsigned long long)n, ROUNDS, K);

    srand((unsigned)time(NULL));

    while (1) {
        int cfd = accept(sfd, NULL, NULL);
        printf("\nНовое подключение\n");

        send(cfd, &n, sizeof(n), 0);
        int kk = K;
        send(cfd, &kk, sizeof(kk), 0);

        int success = 1;

        for (int round = 0; round < ROUNDS; round++) {
            uint64_t x;
            if (recv_all(cfd, &x, sizeof(x)) < 0) { success = 0; break; }

            unsigned char e[K];
            for (int i = 0; i < K; i++) e[i] = rand() & 1;
            send(cfd, e, K, 0);

            uint64_t y;
            if (recv_all(cfd, &y, sizeof(y)) < 0) { success = 0; break; }

            uint64_t lhs = powmod(y, 2, n);
            uint64_t rhs = x;
            for (int i = 0; i < K; i++)
                if (e[i]) rhs = mulmod(rhs, v[i], n);

            int ok = (lhs == rhs);
            if (!ok) success = 0;

            printf("Раунд %2d: %s\n", round + 1, ok ? "OK" : "FAIL");
            if (!ok) break;
        }

        printf("Результат: %s\n", success ? "УСПЕХ" : "ПРОВАЛ");
        send(cfd, success ? "OK" : "FAIL", 4, 0);
        close(cfd);
    }
    return 0;
}