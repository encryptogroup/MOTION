#include <inttypes.h>

#define WIDTH 5
#define HEIGHT 5

typedef struct
{
	int32_t m[HEIGHT][WIDTH];
} InputA;

typedef struct {
	int32_t x, y;
} InputB;

typedef int32_t Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	return INPUT_A.m[INPUT_B.y][INPUT_B.x];
}
