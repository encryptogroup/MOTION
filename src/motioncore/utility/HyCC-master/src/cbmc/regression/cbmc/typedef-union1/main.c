
typedef union tag_union_name
{
  int x;
  float y;
} MYUNION;

void fun()
{
  union tag_union_name tag_union_var = {1};
  MYUNION myunion_var = {.y = 2.1f};
}
