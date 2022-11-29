#include <inttypes.h>

typedef int8_t InputA;
typedef int8_t InputB;
typedef int8_t Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	return INPUT_A * INPUT_B;
}

