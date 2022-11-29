typedef struct Node_
{
	struct Node_ *next;
	struct Node_ *prev;
	void *data;
} Node;

void mpc_main()
{
	Node a, b;
	a.next = &a;
	a.prev = &b;
	b = a;

	Node *p = b.prev;

	Node arr[20];
	arr[17l] = b;

	Node *p1 = arr[17l].next;
}
