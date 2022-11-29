#include <inttypes.h>

#define INT_BITS 16

typedef int16_t InputA;
typedef int16_t InputB;
typedef int16_t Output;

int16_t mod_mul(int16_t x, int16_t y, int16_t mod)
{
	return ((int32_t)x * (int32_t)y) % (int32_t)mod;
}

int16_t mod_exp(int16_t base, int16_t exp, int16_t mod)
{
	int16_t result = 1;
	base %= mod;
	for(int16_t i=0; i < INT_BITS && exp; i++)
	{
		if(exp & 1)
			result = mod_mul(result, base, mod);

		exp = exp >> 1;
		base = mod_mul(base, base, mod);
	}

	return result;
}

Output mpc_main(InputA INPUT_A_base, InputB INPUT_B_exp)
{
	return mod_exp(INPUT_A_base, INPUT_B_exp, INPUT_A_base ^ INPUT_B_exp);
}

