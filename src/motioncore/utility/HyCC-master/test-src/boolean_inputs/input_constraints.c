_Bool is_valid_input(InputA a, InputB b)
{
	// We encode boolean INPUTs using a single bit, which means the only values
	// they can take is zero or one. In contrast, CBMC uses CHAR_BIT bits to
	// encode a boolean value (as is required by the C standard), thus allowing
	// more values than zero and one. Here, we restrict boolean INPUTs to the
	// expected values.

	for(int i = 0; i < ARRAY_LENGTH; ++i)
	{
		if(a.data[i] != 0 && a.data != 1)
			return 0;

		if(b.data[i] != 0 && b.data != 1)
			return 0;
	}

	return 1;
}
