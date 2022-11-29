typedef struct Node_
{
	struct Node_ *next;
	struct Node_ *prev;
	void *data;
} Node;

typedef struct List_
{
	Node sentinel;
} List;

void list_init(List *list)
{
	list->sentinel.next = &list->sentinel;
	list->sentinel.prev = &list->sentinel;
}

Node* list_begin(List *list)
{
	return list->sentinel.next;
}

Node* list_end(List *list)
{
	return &list->sentinel;
}

void insert(Node *pos, Node *item)
{
	item->next = pos;
	item->prev = pos->prev;
	pos->prev->next = item;
	pos->prev = item;
}

void mpc_main()
{
	List list;
	list_init(&list);

	// list.sentinel.next => list.sentinel
	// list.sentinel.prev => list.sentinel

	Node a, b;
	insert(list_end(&list), &a);
	
	// a.next => list.sentinel
	// a.prev => list.sentinel
	// list.sentinel.next => {list.sentinel, a}
	// list.sentinel.prev => {list.sentinel, a}

	insert(list_end(&list), &b);

	// b.next => list.sentinel
	// b.prev => {list.sentinel, a}
	// a.next => {list.sentinel, b}
	// a.prev => list.sentinel
	// list.sentinel.next => {list.sentinel, a, b}
	// list.sentinel.prev => {list.sentinel, a, b}
}
