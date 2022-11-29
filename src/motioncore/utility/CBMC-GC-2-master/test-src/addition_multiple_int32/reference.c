#include <inttypes.h>

typedef struct { int32_t m[2]; } InputA;
typedef int32_t InputB;
typedef int32_t Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	return INPUT_A.m[0] + INPUT_B + INPUT_A.m[1] - INPUT_B + 100;
}

