#include <stdio.h>
#include <stdint.h>

// constants for the Mersenne Twister algorithm
#define N 624
#define M 397
#define MATRIX_A 0x9908b0dfUL
#define UPPER_MASK 0x80000000UL
#define LOWER_MASK 0x7fffffffUL

static uint32_t mt[N];
static int mti = N + 1;


// Initialize the generator from seed
void init_genrand(uint32_t seed)
{
    mt[0] = seed & 0xffffffffUL;
    for (mti = 1; mti < N; mti++) {
        mt[mti] = (1812433253UL * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti);
        mt[mti] &= 0xffffffffUL;
    }
}

// Generate random 32-bit integer.
uint32_t genrand_int32(void)
{
    uint32_t y;
    static uint32_t mag01[2] = {0x0UL, MATRIX_A};

    if (mti >= N) {
        int kk;

        // If init_genrand has not been initialized, use a default seed.
        if (mti == N+1)
            init_genrand(5489UL);

        for (kk = 0; kk < N - M; kk++) {
            y = (mt[kk] & UPPER_MASK) | (mt[kk+1] & LOWER_MASK);
            mt[kk] = mt[kk+M] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        for (; kk < N-1; kk++) {
            y = (mt[kk] & UPPER_MASK) | (mt[kk+1] & LOWER_MASK);
            mt[kk] = mt[kk+(M-N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        y = (mt[N-1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
        mt[N-1] = mt[M-1] ^ (y >> 1) ^ mag01[y & 0x1UL];

        // Reset index
        mti = 0;
    }

    // Get next number from the state
    y = mt[mti++];

    // Tempering -> Improve randomness of Y
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);

    return y;
}

int main(void)
{
    // Define a seed value
    uint32_t seed = 18UL;

    // Initialize generator with the seed
    init_genrand(seed);

    // Print 10 different numbers
    for (int i = 0; i < 10; i++) {
        printf("Random number %d: %u\n", i + 1, genrand_int32());
    }
    return 0;
}