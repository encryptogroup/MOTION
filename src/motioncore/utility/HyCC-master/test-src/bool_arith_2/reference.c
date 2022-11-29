typedef int InputA;
typedef int InputB;
typedef int Output;

int mul(int a, int b)
{
	return a * b * 3;
}

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	int prod = mul(INPUT_A, INPUT_B);
	return ~prod + 1;
}

