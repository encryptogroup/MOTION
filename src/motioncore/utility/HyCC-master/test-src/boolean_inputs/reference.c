#include <inttypes.h>

#define ARRAY_LENGTH 5

typedef struct
{
	_Bool data[ARRAY_LENGTH];
} BoolArray;

typedef BoolArray InputA;
typedef BoolArray InputB;
typedef int32_t Output;

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	Output result = 0;
	for(int i = 0; i < ARRAY_LENGTH; i++)
	{
		if(INPUT_A.data[i] == INPUT_B.data[i])
			result++;
	}

	return result;
}

