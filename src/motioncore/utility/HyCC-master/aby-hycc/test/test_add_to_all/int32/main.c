typedef int int_t;

typedef struct
{
	int_t a[5];
} ArrayInt5;


typedef ArrayInt5 InputA;
typedef ArrayInt5 InputB;
typedef int_t Output;

void add_to_all(int_t *INOUT_arr, int_t CONST_len, int_t amount)
{
	for(int_t i = 0; i < CONST_len; ++i)
		INOUT_arr[i] += amount;
}

int_t sum(int_t *arr, int_t CONST_len)
{
	int_t acc = 0;
	for(int_t i = 0; i < CONST_len; ++i)
		acc += arr[i];

	return acc;
}

int_t mpc_main(ArrayInt5 INPUT_A, ArrayInt5 INPUT_B)
{
	add_to_all(INPUT_A.a, 5, 33);
	add_to_all(INPUT_B.a, 5, 49);

	return sum(INPUT_A.a, 3) + sum(INPUT_B.a, 4);
}

