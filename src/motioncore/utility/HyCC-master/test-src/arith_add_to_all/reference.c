typedef struct
{
	char dummy; // Dummy variable to test if byte offset of `a` is correctly calculated
	int a[5];
} ArrayInt5;


typedef ArrayInt5 InputA;
typedef ArrayInt5 InputB;
typedef int Output;

void add_to_all(int *INOUT_arr, int CONST_len, int amount)
{
	for(int i = 0; i < CONST_len; ++i)
		INOUT_arr[i] += amount;
}

int sum(int *arr, int CONST_len)
{
	int acc = 0;
	for(int i = 0; i < CONST_len; ++i)
		acc += arr[i];

	return acc;
}

int mpc_main(ArrayInt5 INPUT_A, ArrayInt5 INPUT_B)
{
	add_to_all(INPUT_A.a, 5, 33);
	add_to_all(INPUT_B.a, 5, 49);

	return sum(INPUT_A.a, 3) + sum(INPUT_B.a, 4);
}

