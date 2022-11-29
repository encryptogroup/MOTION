void mpc_main()
{
	int a;
	int *p = &a;
	int **pp = &p;

	int b;
	*pp = &b;
}
