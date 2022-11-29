_Bool is_valid_input(InputA a, InputB b)
{
	return b.x >= 0 && b.x < WIDTH && b.y >= 0 && b.y < HEIGHT;
}
