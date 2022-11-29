#include <inttypes.h>

typedef int32_t InputA;

typedef struct
{
	int16_t m[3];
} InputB;

typedef struct
{
	int32_t a, b;
} Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	INPUT_A += 3;
	Output out = {INPUT_A++, 0};

	for(int i = 0; i < 3; ++i)
		INPUT_B.m[i] += INPUT_A;

	INPUT_A = 0;
	for(int i = 0; i < 3; ++i)
		INPUT_A += INPUT_B.m[i];

	out.b = INPUT_A * out.a;
	return out;
}
