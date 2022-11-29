#include <inttypes.h>

typedef struct
{
	int8_t m[3];
} Input;

typedef Input InputA;
typedef Input InputB;
typedef int8_t Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	return INPUT_A.m[0] * INPUT_B.m[0] * INPUT_A.m[1] * INPUT_B.m[1] * INPUT_A.m[2] * INPUT_B.m[2];
}

