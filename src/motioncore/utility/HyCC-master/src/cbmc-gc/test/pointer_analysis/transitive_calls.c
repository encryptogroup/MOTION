int* foo(int *x) { return x; }

int* bar(int *y)
{
	return foo(y);
}

// Ensures that the call to `foo()` is treated differently for each argument even though it is
// called from the same call-site.
void mpc_main()
{
	int a, b;
	int *pa = bar(&a);
	int *pb = bar(&b);
}
