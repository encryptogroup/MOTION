typedef struct Entry_
{
	int *pa, *pb;
} Entry;

// Checks whether we can distinguish between `entries[...].pa` and `entries[...].pb`.
void mpc_main()
{
	int a, b, c, idx1, idx2, idx3, idx4;
	Entry entries[20];
	entries[idx1].pa = &a;
	entries[idx1].pb = &b;

	int *pa = entries[idx2].pa;
	int *pb = entries[idx3].pb;

	Entry *ent1 = &entries[idx4];
	ent1->pa = &c;

	Entry *ent2 = &entries[15l];
	ent2->pb = 0;

	int *p1 = ent1->pb;
	int *p2 = ent2->pa;
}
