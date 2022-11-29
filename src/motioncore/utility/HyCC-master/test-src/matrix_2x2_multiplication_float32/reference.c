#include "../float32.h"
#include <inttypes.h>

#define DIMENSION 2

typedef struct
{
	uint32_t m[DIMENSION][DIMENSION];
} Matrix;

typedef Matrix InputA;
typedef Matrix InputB;
typedef Matrix Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	Output out;

	for(uint8_t row = 0; row < DIMENSION; ++row)
	{
		for(uint8_t col = 0; col < DIMENSION; ++col)
		{
			uint32_t acc = 0;
			for(uint8_t i = 0; i < DIMENSION; ++i)
				acc = float32_add(acc, float32_mul(INPUT_A.m[row][i], INPUT_B.m[i][col]));

			out.m[row][col] = acc;
		}
	}

	return out;
}

