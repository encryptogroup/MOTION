int mul(int a, int b)
{
	return a * b;
}

int mpc_main(int INPUT_A, int INPUT_B)
{
	// Unused return value
	int prod = mul(INPUT_A * 3, INPUT_B);

	int s = INPUT_A * INPUT_B;

	return s;
}

