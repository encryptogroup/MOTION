#include <inttypes.h>

typedef int16_t InputA;
typedef int16_t InputB;
typedef int16_t Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	short sum = INPUT_A + INPUT_B;
	short s = sum + 1;
	short s2 = s + 1;
	return s2 + 1;
}

