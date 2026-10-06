#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#define PORT 8082
#define SALT_LEN SHA256_DIGEST_LENGTH

static void hash_login_password(const char *login, const char *password,
                                unsigned char out[SHA256_DIGEST_LENGTH]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, login, strlen(login));
    SHA256_Update(&c, "|", 1);
    SHA256_Update(&c, password, strlen(password));
    SHA256_Final(out, &c);
}

static void hash_salt_h1(const unsigned char salt[SALT_LEN],
                         const unsigned char h1[SHA256_DIGEST_LENGTH],
                         unsigned char out[SHA256_DIGEST_LENGTH]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, salt, SALT_LEN);
    SHA256_Update(&c, h1, SHA256_DIGEST_LENGTH);
    SHA256_Final(out, &c);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Использование: %s <логин> <пароль>\n", argv[0]);
        return 1;
    }
    const char *login    = argv[1];
    const char *password = argv[2];

    /* Локально считаем h1 = H(login || '|' || password) */
    unsigned char h1[SHA256_DIGEST_LENGTH];
    hash_login_password(login, password, h1);

    /* Подключаемся к серверу */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    /* 1) Отправляем логин */
    send(fd, login, strlen(login), 0);

    /* 2) Получаем соль */
    unsigned char salt[SALT_LEN];
    if (recv(fd, salt, SALT_LEN, MSG_WAITALL) != SALT_LEN) {
        fprintf(stderr, "Не удалось получить соль\n");
        close(fd);
        return 1;
    }

    /* 3) A = H(salt || h1) */
    unsigned char A[SHA256_DIGEST_LENGTH];
    hash_salt_h1(salt, h1, A);
    send(fd, A, sizeof(A), 0);

    /* 4) Читаем ответ сервера */
    char resp[5] = {0};
    recv(fd, resp, 4, 0);
    printf("Аутентификация: %s\n", resp);

    close(fd);
    return 0;
}