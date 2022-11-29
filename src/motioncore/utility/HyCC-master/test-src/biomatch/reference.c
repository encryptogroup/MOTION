#include <inttypes.h>

#define N 10
#define K 4


typedef int32_t int_t;

typedef struct
{
	int_t db[N][K];
} InputA;

typedef struct
{
	int_t sample[K];
} InputB;

typedef int_t Output;


int_t match(int_t x[K], int_t y[K])
{
	int_t r = 0;
	for(int i = 0; i < K; i++)
	{
		int t = (x[i]-y[i]);
		r+= t*t;
	}

	return r;
}

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	int_t best_match = match(INPUT_A.db[0], INPUT_B.sample);;

	for(int i = 1; i < N; i++)
	{
		int_t res = match(INPUT_A.db[i], INPUT_B.sample);
		if(res < best_match)
			best_match = res;
	}

	return best_match;
}

