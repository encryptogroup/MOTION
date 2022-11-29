typedef struct _Inner
{
	char c;
	long l;
	short s[10];
	struct _Inner *pi;
} Inner;

// sizeof(Inner) == 48

typedef struct
{
	Inner i;
	Inner ia[5];
	int *p;
} Outer;

void mpc_main()
{
	Outer outer;
	char *b = (char*)&outer;
	*b = 3;
	b += 4l;
	*b = 23;

	char *inner_c = &outer.i.c;
	long *inner_l = &outer.i.l;

	Inner ina;
	Inner inb;
	outer.ia[2l].pi = &ina;
	outer.ia[3l].pi = &inb;

	Inner *pia = outer.ia[2l].pi;
	Inner *pib = outer.ia[3l].pi;

	Inner inc;
	pia->pi = &inc;
	Inner *pic = ina.pi;
}
