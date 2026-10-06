#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#define PORT       8083
#define BUF        256
#define CHAIN_LEN  1000
#define WINDOW     50

typedef struct {
    char          login[64];
    unsigned char cur[SHA256_DIGEST_LENGTH];
    int           authenticated;
} User;

static User users[8];
static int  un = 0;

static User *find_user(const char *login) {
    for (int i = 0; i < un; i++)
        if (!strcmp(users[i].login, login)) return &users[i];
    return NULL;
}

static int hex_to_bytes(const char *hex, unsigned char out[SHA256_DIGEST_LENGTH]) {
    if (strlen(hex) != SHA256_DIGEST_LENGTH * 2) return 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return 0;
        out[i] = (unsigned char)b;
    }
    return 1;
}

int main(void) {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sfd, (struct sockaddr*)&addr, sizeof(addr));
    listen(sfd, 4);

    printf("Сервер Лэмпорта слушает порт %d (цепочка %d, окно %d)\n",
           PORT, CHAIN_LEN, WINDOW);

    while (1) {
        int cfd = accept(sfd, NULL, NULL);
        char buf[BUF] = {0};
        recv(cfd, buf, BUF - 1, 0);

        char *cmd   = strtok(buf, " ");
        char *login = strtok(NULL, " ");
        char *hex   = strtok(NULL, " ");

        if (!cmd || !login || !hex) {
            send(cfd, "BAD", 3, 0);
            close(cfd);
            continue;
        }

        unsigned char y[SHA256_DIGEST_LENGTH];
        if (!hex_to_bytes(hex, y)) {
            send(cfd, "BADHEX", 6, 0);
            close(cfd);
            continue;
        }

        if (!strcmp(cmd, "REG")) {
            if (find_user(login)) {
                send(cfd, "EXISTS", 6, 0);
                close(cfd);
                continue;
            }
            User *u = &users[un++];
            strncpy(u->login, login, sizeof(u->login) - 1);
            memcpy(u->cur, y, SHA256_DIGEST_LENGTH);
            u->authenticated = 0;
            send(cfd, "REG_OK", 6, 0);
            printf("Зарегистрирован: %s\n", login);
        }
        else if (!strcmp(cmd, "AUTH")) {
            User *u = find_user(login);
            int ok = 0;

            if (u) {
                /* Проверяем: H^k(y) == u->cur, k = 1..WINDOW */
                unsigned char t[SHA256_DIGEST_LENGTH];
                memcpy(t, y, SHA256_DIGEST_LENGTH);

                for (int k = 1; k <= WINDOW; k++) {
                    unsigned char h[SHA256_DIGEST_LENGTH];
                    SHA256(t, SHA256_DIGEST_LENGTH, h);
                    memcpy(t, h, SHA256_DIGEST_LENGTH);

                    if (memcmp(t, u->cur, SHA256_DIGEST_LENGTH) == 0) {
                        ok = 1;
                        break;
                    }
                }

                if (ok) {
                    memcpy(u->cur, y, SHA256_DIGEST_LENGTH);
                    u->authenticated++;
                }
            }

            send(cfd, ok ? "AUTH_OK" : "AUTH_FAIL", ok ? 7 : 9, 0);
            printf("Аутентификация %s: %s (#%d)\n",
                   login, ok ? "OK" : "FAIL", u ? u->authenticated : 0);
        }
        else {
            send(cfd, "BAD", 3, 0);
        }

        close(cfd);
    }
    return 0;
}