#include <inttypes.h>

typedef struct
{
	int32_t x, y;
} Vec2;

typedef Vec2 InputA;
typedef Vec2 InputB;
typedef int32_t Output;

int32_t sqrt_newton(int32_t value)
{
	int32_t result = value;
	for(int32_t i = 0; i < 20 && result != 0; ++i)
		result = (result + value / result) >> 1;

	return result;
}

int32_t distance(int32_t x1, int32_t y1, int32_t x2, int32_t y2)
{
	int32_t dx = x1 - x2;
	int32_t dy = y1 - y2;
	return sqrt_newton(dx*dx + dy*dy);
}

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	return distance(INPUT_A.x, INPUT_A.y, INPUT_B.x, INPUT_B.y);
}
