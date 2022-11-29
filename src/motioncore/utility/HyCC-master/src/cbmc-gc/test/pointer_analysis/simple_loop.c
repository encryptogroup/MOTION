// Tests whether the loop is iterated at least twice so that `p` may point to `a`.
int* mpc_main()
{
	int a = 0;
	int *p = 0;
	int *p2 = 0;

	while(1)
	{
		p = p2;
		p2 = &a;
	}

	return p;
}
