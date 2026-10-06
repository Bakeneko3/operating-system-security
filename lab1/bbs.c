#include <stdio.h>

#include "bbs.h"

static int64_t x = (46336 * 46336) % 2147050637;

int8_t bbs(void)
{
    x = (x * x) % 2147050637;
    return x & 1;
}

/* with random seed */
static int8_t cnt = 10;

static void bbs_seed(int32_t seed)
{
    x = (seed * seed) % 2147050637;
}

static int32_t random_seed(void)
{
    int32_t seed = 0;

    FILE *file = fopen("/dev/random", "rb");
    if (!file) {
        return -1;
    }

    fread(&seed, sizeof(seed), 1, file);
    fclose(file);

    return seed;
}

static int32_t gcd(int32_t seed, int32_t n)
{
    while (n != 0) {
        int32_t tmp = n;
        n = seed % n;
        seed = tmp;
    }

    return seed;
}

int8_t rsbbs(void)
{
    if (cnt >= 10) {
        int32_t seed = 0;

        do {
            seed = random_seed();
        } while (gcd(seed, 2147050637) != 1);

        bbs_seed(seed);
        cnt = 0;
    }

    cnt++;
    return bbs();
}
