_Bool is_valid_input(InputA a, InputB b)
{
	return b >= 0 && (a ^ b) > 0;
}
