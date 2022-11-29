#define STATIC_ASSERT(condition) \
  int some_array##__LINE__[(condition) ? 1 : -1];

struct S
{
  int x;
};

int main()
{
  struct S s;
  __typeof__(*((void *)&s.x)) *_s=&s.x;
  STATIC_ASSERT(sizeof(*_s)==1);
  return 0;
}
