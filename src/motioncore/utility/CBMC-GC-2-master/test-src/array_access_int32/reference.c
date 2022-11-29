#include <inttypes.h>

#define NUM_ELEMENTS 32

typedef struct
{
	int32_t m[NUM_ELEMENTS];
} InputA;

typedef int32_t InputB;
typedef int32_t Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	return INPUT_A.m[INPUT_B];
}
