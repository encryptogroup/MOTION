int mul(int a, int b)
{
	return a * b;
}

int mpc_main(int INPUT_A, int INPUT_B)
{
	int prod = mul(INPUT_A * 3, INPUT_B);
	for(int i = 0; i < 5; ++i)
		prod = mul(INPUT_A, prod + 3);

	int s = INPUT_A * INPUT_B;

	return prod * s;
}

