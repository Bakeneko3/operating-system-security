#ifndef BBS_H

#include <stdint.h>

#define BBS_H

/*
 * p 28643
 * q 74959
 * n 2147050637
 * seed 46336
 */

int8_t bbs(void);

/* with random seed */
int8_t rsbbs(void);

#endif /* BBS_H */
