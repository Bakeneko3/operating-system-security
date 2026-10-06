#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX 64
#define R_  1
#define W_  2

typedef struct { char name[32]; int alive; } Entity;
typedef struct {
    char name[32];
    int  alive;
    int  parent[MAX];   /* список родительских ролей (индексы) */
    int  parent_n;
} Role;
typedef struct {
    char name[32];
    int  alive;
    int  roles[MAX];    /* роли, назначенные пользователю */
    int  role_n;
    int  active_role;   /* индекс активной роли или -1 */
} User;

static Entity objs[MAX];  static int obj_n = 0;
static Role   roles[MAX]; static int role_n = 0;
static User   users[MAX]; static int user_n = 0;

/* Perm[r][o] — права роли r на объект o */
static int Perm[MAX][MAX];

/* ---- Утилиты ---- */

static int find_obj(const char *n) {
    for (int i = 0; i < obj_n; i++)
        if (objs[i].alive && !strcmp(objs[i].name, n)) return i;
    return -1;
}
static int find_role(const char *n) {
    for (int i = 0; i < role_n; i++)
        if (roles[i].alive && !strcmp(roles[i].name, n)) return i;
    return -1;
}
static int find_user(const char *n) {
    for (int i = 0; i < user_n; i++)
        if (users[i].alive && !strcmp(users[i].name, n)) return i;
    return -1;
}

/* Рекурсивный сбор эффективных ролей (роль + все её родители транзитивно) */
static void collect_effective(int r, int *out, int *out_n, int *mark) {
    if (mark[r]) return;
    mark[r] = 1;
    out[(*out_n)++] = r;
    for (int i = 0; i < roles[r].parent_n; i++) {
        collect_effective(roles[r].parent[i], out, out_n, mark);
    }
}

/* Собирает эффективные права пользователя в текущей активной роли */
static int effective_rights(int u, int o) {
    if (users[u].active_role < 0) return 0;

    int eff[MAX], eff_n = 0, mark[MAX] = {0};
    collect_effective(users[u].active_role, eff, &eff_n, mark);

    int mask = 0;
    for (int i = 0; i < eff_n; i++) {
        mask |= Perm[eff[i]][o];
    }
    return mask;
}

/* Вывод всех эффективных ролей пользователя */
static void print_effective(int u) {
    if (users[u].active_role < 0) { printf("(роль не активна)"); return; }
    int eff[MAX], eff_n = 0, mark[MAX] = {0};
    collect_effective(users[u].active_role, eff, &eff_n, mark);
    printf("%s", roles[users[u].active_role].name);
    for (int i = 1; i < eff_n; i++) printf(", %s", roles[eff[i]].name);
}

/* ---- Команды ---- */

static void cmd_create_object(const char *n) {
    if (find_obj(n) >= 0) { printf("Объект '%s' уже есть\n", n); return; }
    strncpy(objs[obj_n].name, n, 31);
    objs[obj_n].alive = 1;
    obj_n++;
    printf("Создан объект %s\n", n);
}

static void cmd_create_role(const char *n) {
    if (find_role(n) >= 0) { printf("Роль '%s' уже есть\n", n); return; }
    strncpy(roles[role_n].name, n, 31);
    roles[role_n].alive = 1;
    roles[role_n].parent_n = 0;
    role_n++;
    printf("Создана роль %s\n", n);
}

static void cmd_create_user(const char *n) {
    if (find_user(n) >= 0) { printf("Пользователь '%s' уже есть\n", n); return; }
    strncpy(users[user_n].name, n, 31);
    users[user_n].alive = 1;
    users[user_n].role_n = 0;
    users[user_n].active_role = -1;
    user_n++;
    printf("Создан пользователь %s\n", n);
}

/* Добавить/убрать право роли на объект */
static void cmd_add_perm(const char *role, const char *obj, const char *right) {
    int r = find_role(role), o = find_obj(obj);
    if (r < 0) { printf("Нет роли '%s'\n", role); return; }
    if (o < 0) { printf("Нет объекта '%s'\n", obj); return; }
    int bit = 0;
    if (strchr(right, 'r')) bit |= R_;
    if (strchr(right, 'w')) bit |= W_;
    if (!bit) { printf("Права должны содержать 'r' и/или 'w'\n"); return; }
    Perm[r][o] |= bit;
    printf("Роль %s получила право '%s' на %s\n", role, right, obj);
}

/* Установить родительскую роль: child наследует parent */
static void cmd_set_parent(const char *child, const char *parent) {
    int c = find_role(child), p = find_role(parent);
    if (c < 0) { printf("Нет роли '%s'\n", child); return; }
    if (p < 0) { printf("Нет роли '%s'\n", parent); return; }
    if (c == p) { printf("Роль не может наследовать себя\n"); return; }
    for (int i = 0; i < roles[c].parent_n; i++)
        if (roles[c].parent[i] == p) { printf("Уже наследует\n"); return; }
    roles[c].parent[roles[c].parent_n++] = p;
    printf("Роль %s теперь наследует %s\n", child, parent);
}

/* Назначить роль пользователю */
static void cmd_assign(const char *user, const char *role) {
    int u = find_user(user), r = find_role(role);
    if (u < 0) { printf("Нет пользователя '%s'\n", user); return; }
    if (r < 0) { printf("Нет роли '%s'\n", role); return; }
    for (int i = 0; i < users[u].role_n; i++)
        if (users[u].roles[i] == r) { printf("Уже назначена\n"); return; }
    users[u].roles[users[u].role_n++] = r;
    printf("Пользователь %s получил роль %s\n", user, role);
}

/* Смена активной роли пользователя (вход под ролью) */
static void cmd_login(const char *user, const char *role) {
    int u = find_user(user), r = find_role(role);
    if (u < 0) { printf("Нет пользователя '%s'\n", user); return; }
    if (r < 0) { printf("Нет роли '%s'\n", role); return; }
    int has = 0;
    for (int i = 0; i < users[u].role_n; i++)
        if (users[u].roles[i] == r) { has = 1; break; }
    if (!has) { printf("У пользователя %s нет роли %s\n", user, role); return; }
    users[u].active_role = r;
    printf("Пользователь %s активировал роль %s\n", user, role);
    printf("Эффективные роли: "); print_effective(u); printf("\n");
}

/* Выход — снять активную роль */
static void cmd_logout(const char *user) {
    int u = find_user(user);
    if (u < 0) { printf("Нет пользователя\n"); return; }
    users[u].active_role = -1;
    printf("Пользователь %s вышел из активной роли\n", user);
}

/* Попытка доступа */
static void cmd_access(const char *user, const char *obj, int want) {
    int u = find_user(user), o = find_obj(obj);
    if (u < 0) { printf("Нет пользователя '%s'\n", user); return; }
    if (o < 0) { printf("Нет объекта '%s'\n", obj); return; }
    if (users[u].active_role < 0) { printf("Отказ: роль не активна\n"); return; }

    int got = effective_rights(u, o);
    if (got & want) {
        printf("OK: %s %s %s (роль %s)\n",
               user, want == R_ ? "читает" : "пишет", obj,
               roles[users[u].active_role].name);
    } else {
        printf("ОТКАЗ: %s не имеет права '%s' на %s\n",
               user, want == R_ ? "r" : "w", obj);
    }
}

/* Показать права роли (с учётом наследования) */
static void cmd_show_role(const char *rn) {
    int r = find_role(rn);
    if (r < 0) { printf("Нет роли '%s'\n", rn); return; }
    printf("Роль %s:\n", rn);
    printf("  Родители:");
    if (roles[r].parent_n == 0) printf(" (нет)");
    else for (int i = 0; i < roles[r].parent_n; i++)
        printf(" %s", roles[roles[r].parent[i]].name);
    printf("\n  Собственные права:\n");
    int any = 0;
    for (int o = 0; o < obj_n; o++) {
        if (!Perm[r][o]) continue;
        printf("    %-10s : %s%s\n", objs[o].name,
               (Perm[r][o] & R_) ? "r" : "", (Perm[r][o] & W_) ? "w" : "");
        any = 1;
    }
    if (!any) printf("    (нет)\n");

    int eff[MAX], eff_n = 0, mark[MAX] = {0};
    collect_effective(r, eff, &eff_n, mark);
    printf("  Эффективные права (со всеми родителями):\n");
    any = 0;
    for (int o = 0; o < obj_n; o++) {
        int mask = 0;
        for (int i = 0; i < eff_n; i++) mask |= Perm[eff[i]][o];
        if (!mask) continue;
        printf("    %-10s : %s%s\n", objs[o].name,
               (mask & R_) ? "r" : "", (mask & W_) ? "w" : "");
        any = 1;
    }
    if (!any) printf("    (нет)\n");
}

/* Показать состояние пользователя */
static void cmd_show_user(const char *un) {
    int u = find_user(un);
    if (u < 0) { printf("Нет пользователя '%s'\n", un); return; }
    printf("Пользователь %s:\n", un);
    printf("  Назначенные роли:");
    if (users[u].role_n == 0) printf(" (нет)");
    else for (int i = 0; i < users[u].role_n; i++)
        printf(" %s", roles[users[u].roles[i]].name);
    printf("\n  Активная роль: ");
    if (users[u].active_role < 0) printf("(не активна)\n");
    else { printf("%s\n", roles[users[u].active_role].name); }
}

/* ---- Демо ---- */

static void cmd_demo(void) {
    /* Сброс */
    obj_n = role_n = user_n = 0;
    memset(objs, 0, sizeof(objs));
    memset(roles, 0, sizeof(roles));
    memset(users, 0, sizeof(users));
    memset(Perm, 0, sizeof(Perm));

    printf("=== Демо RBAC ===\n");

    /* Объекты */
    cmd_create_object("public_doc");
    cmd_create_object("internal_doc");
    cmd_create_object("secret_doc");

    /* Роли */
    cmd_create_role("guest");       /* базовая: только чтение public */
    cmd_create_role("employee");    /* наследует guest + чтение internal + запись public */
    cmd_create_role("manager");     /* наследует employee + чтение/запись internal */
    cmd_create_role("admin");       /* наследует manager + всё на secret */

    /* Права базовой роли guest */
    cmd_add_perm("guest", "public_doc", "r");

    /* employee: + чтение internal, + запись public */
    cmd_add_perm("employee", "internal_doc", "r");
    cmd_add_perm("employee", "public_doc",   "w");

    /* manager: + чтение и запись internal */
    cmd_add_perm("manager", "internal_doc", "rw");

    /* admin: всё на secret */
    cmd_add_perm("admin", "secret_doc", "rw");

    /* Иерархия: employee >= guest, manager >= employee, admin >= manager */
    cmd_set_parent("employee", "guest");
    cmd_set_parent("manager",  "employee");
    cmd_set_parent("admin",    "manager");

    /* Пользователи */
    cmd_create_user("alice");
    cmd_create_user("bob");
    cmd_create_user("charlie");

    cmd_assign("alice",   "guest");
    cmd_assign("alice",   "employee");
    cmd_assign("bob",     "manager");
    cmd_assign("charlie", "admin");

    printf("\n--- Просмотр ролей ---\n");
    cmd_show_role("employee");
    cmd_show_role("admin");

    printf("\n--- Работа alice ---\n");
    cmd_login("alice", "guest");
    cmd_access("alice", "public_doc",   R_);   /* OK */
    cmd_access("alice", "internal_doc", R_);   /* отказ — guest не видит internal */
    cmd_access("alice", "public_doc",   W_);   /* отказ — guest только читает */

    cmd_login("alice", "employee");
    cmd_access("alice", "internal_doc", R_);   /* OK — employee наследует guest + своё */
    cmd_access("alice", "public_doc",   W_);   /* OK — employee может писать public */
    cmd_access("alice", "public_doc",   R_);   /* OK — через наследование от guest */
    cmd_access("alice", "secret_doc",   R_);   /* отказ */

    printf("\n--- Работа bob ---\n");
    cmd_login("bob", "manager");
    cmd_access("bob", "internal_doc", W_);   /* OK */
    cmd_access("bob", "secret_doc",   R_);   /* отказ */

    printf("\n--- Работа charlie ---\n");
    cmd_login("charlie", "admin");
    cmd_access("charlie", "secret_doc", R_);   /* OK */
    cmd_access("charlie", "secret_doc", W_);   /* OK */
    cmd_access("charlie", "public_doc", R_);   /* OK через всю цепочку наследования */
    cmd_access("charlie", "public_doc", W_);   /* OK через всю цепочку */

    printf("\n--- Смена роли alice на guest обратно ---\n");
    cmd_login("alice", "guest");
    cmd_access("alice", "internal_doc", R_);   /* отказ — вернулись к guest */
}

/* ---- main ---- */

static void help(void) {
    printf("\nКоманды:\n");
    printf("  co <o>                    — создать объект\n");
    printf("  cr <r>                    — создать роль\n");
    printf("  cu <u>                    — создать пользователя\n");
    printf("  perm <r> <o> <r|w|rw>     — дать роли право на объект\n");
    printf("  parent <child> <parent>   — child наследует права parent\n");
    printf("  assign <u> <r>            — назначить роль пользователю\n");
    printf("  login <u> <r>             — активировать роль (смена роли)\n");
    printf("  logout <u>                — снять активную роль\n");
    printf("  read <u> <o>              — попытка чтения\n");
    printf("  write <u> <o>             — попытка записи\n");
    printf("  showrole <r>              — показать права роли\n");
    printf("  showuser <u>              — показать роли пользователя\n");
    printf("  demo                      — демонстрация\n");
    printf("  help                      — справка\n");
    printf("  quit                      — выход\n\n");
}

int main(void) {
    printf("RBAC — управление доступом на основе ролей\n");
    help();

    char line[256];
    while (1) {
        printf("> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;

        char cmd[16], a[32], b[32], c[32];
        int k = sscanf(line, "%15s %31s %31s %31s", cmd, a, b, c);
        if (k < 1) continue;

        if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit")) break;
        else if (!strcmp(cmd, "help")) help();
        else if (!strcmp(cmd, "demo")) cmd_demo();
        else if (!strcmp(cmd, "co")     && k >= 2) cmd_create_object(a);
        else if (!strcmp(cmd, "cr")     && k >= 2) cmd_create_role(a);
        else if (!strcmp(cmd, "cu")     && k >= 2) cmd_create_user(a);
        else if (!strcmp(cmd, "perm")   && k >= 4) cmd_add_perm(a, b, c);
        else if (!strcmp(cmd, "parent") && k >= 3) cmd_set_parent(a, b);
        else if (!strcmp(cmd, "assign") && k >= 3) cmd_assign(a, b);
        else if (!strcmp(cmd, "login")  && k >= 3) cmd_login(a, b);
        else if (!strcmp(cmd, "logout") && k >= 2) cmd_logout(a);
        else if (!strcmp(cmd, "read")   && k >= 3) cmd_access(a, b, R_);
        else if (!strcmp(cmd, "write")  && k >= 3) cmd_access(a, b, W_);
        else if (!strcmp(cmd, "showrole") && k >= 2) cmd_show_role(a);
        else if (!strcmp(cmd, "showuser") && k >= 2) cmd_show_user(a);
        else printf("Неизвестная команда. 'help' для справки.\n");
    }
    printf("Выход.\n");
    return 0;
}