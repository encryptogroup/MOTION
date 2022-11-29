#include <string.h>

typedef unsigned DT;

#define SQRTN 30
#define N (SQRTN*SQRTN)


DT activate_sqr(DT val)
{
	DT res = val*val;
	return res;
}

void standard_map(DT *a, DT *b, DT *OUTPUT_res, int len)
{
	for(int i = 0; i < len; i++)
		OUTPUT_res[i] = activate_sqr(a[i]+b[i]);
}

void log_map(DT *a, DT *b, DT *OUTPUT_res, int sqrt_len)
{
	DT cp1[sqrt_len];
	DT cp2[sqrt_len];
	DT im[sqrt_len];
	for(int i = 0; i < sqrt_len; i++)
	{
		memcpy(cp1, a, sqrt_len*sizeof(DT));
		memcpy(cp2, b, sqrt_len*sizeof(DT));
		standard_map(cp1, cp2, im, sqrt_len);
		memcpy(OUTPUT_res+i*sqrt_len, im, sqrt_len*sizeof(DT));
	}
}


typedef struct 
{
	DT data[N];
} InputA;

typedef struct
{
	DT data[N];
} InputB;

typedef struct
{
	DT output[N];
} Output;


Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	Output res;
	log_map(INPUT_A.data, INPUT_B.data, res.output, SQRTN);

	return res;
}
