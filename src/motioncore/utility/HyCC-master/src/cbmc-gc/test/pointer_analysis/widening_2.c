// Tests whether widening for write accesses is performed to ensure termination of the pointer
// analysis.
void mpc_main()
{
	int a;
	int* arr[3];
	int **p = arr;
	for(long i = 0; i < 3; ++i, ++p)
		*p = &a;
}
