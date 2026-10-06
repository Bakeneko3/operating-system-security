#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#define PORT 8085
#define BUF  4096

/* 64-битное простое (для демонстрации; в реальности 2048+ бит) */
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

int main(void) {
    /* 1. Слушаем порт */
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sfd, (struct sockaddr*)&addr, sizeof(addr));
    listen(sfd, 4);

    printf("DH-сервер на порту %d\n", PORT);
    printf("p = %llu (0x%llx), g = %llu\n",
           (unsigned long long)P, (unsigned long long)P,
           (unsigned long long)G);

    srand((unsigned)time(NULL));

    while (1) {
        int cfd = accept(sfd, NULL, NULL);
        printf("\nНовое подключение\n");

        /* 2. Получаем A = g^a mod p */
        uint64_t A;
        if (recv_all(cfd, &A, sizeof(A)) < 0) { close(cfd); continue; }
        printf("Получено A = %llu\n", (unsigned long long)A);

        /* 3. Генерируем b и шлём B = g^b mod p */
        uint64_t b = 2 + (uint64_t)rand() * rand() % (P - 3);
        uint64_t B = powmod(G, b, P);
        send(cfd, &B, sizeof(B), 0);
        printf("Отправлено B = %llu\n", (unsigned long long)B);

        /* 4. Считаем общий ключ K = A^b mod p */
        uint64_t K = powmod(A, b, P);
        printf("Общий секрет K = %llu\n", (unsigned long long)K);

        /* 5. KDF: K -> 32-байтовый симметричный ключ */
        unsigned char key[32];
        SHA256((unsigned char*)&K, sizeof(K), key);

        /* 6. Принимаем длину и зашифрованное сообщение */
        uint32_t len;
        if (recv_all(cfd, &len, sizeof(len)) < 0) { close(cfd); continue; }
        if (len > BUF) len = BUF;

        unsigned char buf[BUF];
        if (recv_all(cfd, buf, len) < 0) { close(cfd); continue; }

        xor_crypt(buf, len, key, sizeof(key));

        printf("Расшифрованное сообщение: %.*s\n", (int)len, buf);

        /* 7. Отвечаем клиенту OK */
        send(cfd, "OK", 2, 0);
        close(cfd);
    }
    return 0;
}