// Tests whether widening for read accesses is performed to ensure termination of the pointer
// analysis.
int mpc_main()
{
	int arr[5] = {42, 4, 993, 450, 93};

	int *begin = arr;
	int *end = arr + 5l;
	int sum = 0;
	while(begin != end)
	{
		sum += *begin;
		++begin;
	}

	return sum;
}
