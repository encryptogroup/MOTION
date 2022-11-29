#include <inttypes.h>

typedef int32_t InputA;
typedef int32_t InputB;
typedef int32_t Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	return INPUT_A / INPUT_B;
}

