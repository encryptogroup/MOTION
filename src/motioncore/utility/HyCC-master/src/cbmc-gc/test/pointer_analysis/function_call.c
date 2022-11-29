long* find(long *data, long length, long value)
{
	for(long i = 0; i < length; ++i)
	{
		if(data[i] == value)
			return data + i;
	}

	return 0;
}

void swap_ptrs(int **a, int **b)
{
	int *tmp = *a;
	*a = *b;
	*b = tmp;
}

void mpc_main()
{
	long arr[5];
	long *p = find(arr, 5, 3);

	// Run the same function a second time to make sure arguments are not
	// accidentilly reused.
	long brr[5];
	long *q = find(brr, 5, 3);

	int a, b;
	int *pa = &a, *pb = &b;
	swap_ptrs(&pa, &pb);

	int x, y;
	int *px = &x, *py = &y;
	swap_ptrs(&px, &py);
}
