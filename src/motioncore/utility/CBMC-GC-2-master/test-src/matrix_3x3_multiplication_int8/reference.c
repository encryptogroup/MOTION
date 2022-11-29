#include <inttypes.h>

#define DIMENSION 3

typedef struct
{
	int8_t m[DIMENSION][DIMENSION];
} Matrix3x3;

typedef Matrix3x3 InputA;
typedef Matrix3x3 InputB;
typedef Matrix3x3 Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	Output out;

	for(uint8_t row = 0; row < DIMENSION; ++row)
	{
		for(uint8_t col = 0; col < DIMENSION; ++col)
		{
			int8_t acc = 0;
			for(uint8_t i = 0; i < DIMENSION; ++i)
				acc += INPUT_A.m[row][i] * INPUT_B.m[i][col];

			out.m[row][col] = acc;
		}
	}

	return out;
}

