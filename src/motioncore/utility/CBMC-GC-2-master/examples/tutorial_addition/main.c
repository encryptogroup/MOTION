
// int mpc_main(int INPUT_A, int INPUT_B)
// {
// 	return INPUT_A + INPUT_B;
// }

// typedef signed int fixedptd;
typedef unsigned long long int fixedptd;



fixedptd mpc_main(fixedptd INPUT_A, fixedptd INPUT_B)
{
	// fixedptd c = INPUT_A * INPUT_B;
	// fixedptd d = c + 2;
	// fixedptd d = c/242;
	return INPUT_A * INPUT_B>>2;
}