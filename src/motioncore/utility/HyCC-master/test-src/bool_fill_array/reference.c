typedef struct
{
	int a[5];
} ArrayInt5;


typedef ArrayInt5 InputA;
typedef int InputB;
typedef ArrayInt5 Output;

void fill(int *OUTPUT_arr, int CONST_len, int value)
{
	for(int i = 0; i < CONST_len; ++i)
		OUTPUT_arr[i] = value;
}

ArrayInt5 mpc_main(ArrayInt5 INPUT_A, int INPUT_B)
{
	(void)INPUT_B;

	fill(INPUT_A.a, 5, 993);
	return INPUT_A;
}

