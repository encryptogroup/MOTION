
typedef struct
{
	int x, y;
} Vec2;

int sqrt_newton(int value)
{
	int result = value;
	for(int i = 0; i < 20 && result != 0; ++i)
		result = (result + value / result) >> 1;

	return result;
}

int distance(Vec2 a, Vec2 b)
{
	int dx = a.x - b.x;
	int dy = a.y - b.y;
	return sqrt_newton(dx*dx + dy*dy);
}

int mpc_main(Vec2 INPUT_A, Vec2 INPUT_B)
{
	return distance(INPUT_A, INPUT_B);
}
