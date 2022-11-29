#include <inttypes.h>

typedef struct
{
	int32_t a, b;
} Input;

typedef Input InputA;
typedef Input InputB;
typedef int32_t Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	return INPUT_A.a * INPUT_B.a + INPUT_A.a * 7 + INPUT_B.b * -42 + -INPUT_A.b * INPUT_B.a;
}

