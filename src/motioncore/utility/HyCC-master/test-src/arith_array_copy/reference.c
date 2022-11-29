typedef struct
{
	int a[5];
} ArrayInt5;


typedef ArrayInt5 InputA;
typedef ArrayInt5 InputB;
typedef ArrayInt5 Output;


void copy(int *OUTPUT_dest, int *src, int CONST_len)
{
	for(int i = 0; i < CONST_len; ++i)
		OUTPUT_dest[i] = src[i];
}

Output mpc_main(ArrayInt5 INPUT_A, ArrayInt5 INPUT_B)
{
	Output out;
	copy(out.a, INPUT_A.a, 5);
	copy(out.a, INPUT_B.a, 5);

	return out;
}

