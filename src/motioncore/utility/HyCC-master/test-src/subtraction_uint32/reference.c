#include <inttypes.h>

typedef uint32_t InputA;
typedef uint32_t InputB;
typedef uint32_t Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	return INPUT_A - INPUT_B;
}

