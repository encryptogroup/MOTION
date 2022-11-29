typedef struct
{
	int a[5];
} ArrayInt5;


typedef ArrayInt5 InputA;
typedef ArrayInt5 InputB;
typedef int Output;

int sum(int *arr, int CONST_len)
{
	int acc = 0;
	for(int i = 0; i < CONST_len; ++i)
		acc += arr[i];

	return acc;
}

int mpc_main(ArrayInt5 INPUT_A, ArrayInt5 INPUT_B)
{
	return sum(INPUT_A.a, 5) + sum(INPUT_B.a, 5);
}

