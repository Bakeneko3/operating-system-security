/*
 * gcc bbs.c lab1.c -o lab1
 * ./lab1
 * cp data.txt ~/sts-2_1_2/sts-2.1.2/sts-2.1.2/data/
 * cd ~/sts-2_1_2/sts-2.1.2/sts-2.1.2/
 * ./assess 1048576
 * cat experiments/AlgorithmTesting/finalAnalysisReport.txt
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "bbs.h"

#define SIZE (1024*1024*128) /* 128 MiB */

int main()
{
    /* generate data */
    int8_t *data = (int8_t *)malloc(SIZE * sizeof(int8_t));
    if (!data) {
        return -1;
    }

    for (uint32_t i = 0; i < SIZE; i++) {
        data[i] = 0;
        for (int j = 0; j < 8; j++) {
            data[i] |= (rsbbs() & 1) << (7-j);
        }
    }

    /* write data to file */
    FILE *file = fopen("data.bin", "wb");
    if (!file) {
        return -1;
    }

    fwrite(data, sizeof(int8_t), SIZE, file);

    fclose(file);
    free(data);

    return 0;
}
