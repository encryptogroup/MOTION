/**
 * Example on how to merge two data sets and to perform various analyses
 */
 
#include <string.h>



#define LEN_A 100
#define LEN_B 100
#define ATT_A 1 //Number of attributes
#define ATT_B 1

#include "db.h"

void merge(DT *OUTPUT_db, DT *a, DT *b, unsigned len_a, unsigned len_b) {
	memcpy(OUTPUT_db, a, len_a * sizeof(DT));
	memcpy(OUTPUT_db + len_a, b, len_b * sizeof(DT));
} 


Output mpc_main(InputA INPUT_A, InputB INPUT_B) {
	Output res;
	
	DT db[LEN];
	
	// merge databases
	merge(db, INPUT_A.db, INPUT_B.db, LEN_A, LEN_B);
	// compute? histogram, correlation or
	
	res.joined = LEN;
	res.analysis1 = mean(db, LEN);
	res.analysis2 = variance(db, LEN);
	return res;
} 

#ifdef GCC
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
int main() {
	srand(time(NULL));
	InputA a;
	InputB b;
	for(int i = 0; i < LEN_A; i++) {
		a.db[i] = rand() >> 20;
	}
	for(int i = 0; i < LEN_B; i++) {
		b.db[i] = rand() >> 20;
	}
	Output res = mpc_main(a, b);
	
	printf("Output mean=%d variance=%d\n", res.analysis1, res.analysis2);
	return 0;
}
#endif
