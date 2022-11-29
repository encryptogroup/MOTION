int mul(int a, int b)
{
	return a * b;
}

int add(int a, int b)
{
	return a + b;
}

int mpc_main(int INPUT_A, int INPUT_B)
{
	INPUT_A += 1;
	INPUT_B += 1;

	int a = mul(INPUT_A / INPUT_B, INPUT_B);
	int b = add(INPUT_A & INPUT_B, INPUT_B);

	return a + b;
}

