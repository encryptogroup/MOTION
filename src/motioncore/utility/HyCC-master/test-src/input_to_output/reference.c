#include <inttypes.h>

typedef int32_t InputA;
typedef int32_t InputB;

typedef struct
{
	int32_t a, b;
} Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	Output out = {INPUT_A, INPUT_B};
	return out;
}
