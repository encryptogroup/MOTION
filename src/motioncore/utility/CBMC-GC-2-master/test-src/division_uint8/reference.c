#include <inttypes.h>

typedef uint8_t InputA;
typedef uint8_t InputB;
typedef uint8_t Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	return INPUT_A / INPUT_B;
}

