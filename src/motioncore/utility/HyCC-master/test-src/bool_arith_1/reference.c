typedef int InputA;
typedef int InputB;
typedef int Output;

int boolean(int a, int b)
{
	return a + b;
}

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	return boolean(INPUT_A * INPUT_B + 2, INPUT_B);
}

