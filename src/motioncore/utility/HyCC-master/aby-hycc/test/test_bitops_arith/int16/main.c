#include <inttypes.h>

typedef int16_t int_t;


int_t mul(int_t a, int_t b)
{
	return a * b;
}


int_t add(int_t a, int_t b)
{
	return a + b;
}

int_t sub(int_t a, int_t b)
{
	return a + b;
}

typedef struct
{
	int_t a[3];
} IntArray3;

IntArray3 mpc_main(int_t INPUT_A, int_t INPUT_B)
{
	int_t p = mul(INPUT_A & 0xff00, INPUT_B & 0x0ff0);
	int_t q = add(INPUT_A & 0x0ff0, INPUT_B & 0x00ff);
	int_t r = sub(p & 0x0ff0, p & 0x00ff);

	IntArray3 out = {{p, q, r}};
	return out;
}
