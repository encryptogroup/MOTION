#include <inttypes.h>

#define DIMENSION 3

typedef struct
{
	int32_t m[DIMENSION][DIMENSION];
} Matrix;

int mul(int a, int b)
{
	return a * b;
}

int add(int a, int b)
{
	return a + b;
}

Matrix mpc_main(Matrix a, Matrix b)
{
	Matrix out;

	a.m[1][2] = a.m[2][1] + b.m[0][1];
	a.m[0][1] = a.m[2][1] * b.m[0][1] * a.m[2][2];

	for(uint8_t row = 0; row < DIMENSION; ++row)
	{
		for(uint8_t col = 0; col < DIMENSION; ++col)
		{
			int32_t acc = 0;
			for(uint8_t i = 0; i < DIMENSION; ++i)
				acc = add(acc, mul(a.m[row][i], b.m[i][col]));

			out.m[row][col] = acc;
		}
	}

	out.m[0][0] += 13;

	return out;
}

