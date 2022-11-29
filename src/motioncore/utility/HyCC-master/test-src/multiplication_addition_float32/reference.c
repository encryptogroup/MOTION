#include "../float32.h"

typedef int InputA;
typedef struct
{
	int x, y;
} InputB;

typedef int Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	return float32_mul(float32_add(INPUT_A, INPUT_B.x), INPUT_B.y);
}

