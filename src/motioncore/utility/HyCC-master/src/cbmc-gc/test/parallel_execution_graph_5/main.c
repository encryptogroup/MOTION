// This test ensures that a function call increases the depth by one

int mul(int a, int b)
{
	return a * b;
}

int mpc_main(int INPUT_A, int INPUT_B)
{
	int s = INPUT_A ^ INPUT_B;
	int p = mul(s, INPUT_A);
	return mul(p ^ 7, 3);
}
