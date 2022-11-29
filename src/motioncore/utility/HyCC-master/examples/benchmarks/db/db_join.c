/**
 * Example on how to merge two data sets and to perform various analyses
 */
 
#include <string.h>
#include <stdio.h>



#define LEN_A 50
#define LEN_B 50

#define ATT_A 2 //Number of attributes
#define ATT_B 2


#include "db.h"


size_t cross_join(DT *OUTPUT_db, DT *a, DT *b) {
	size_t id_a = 0;
	size_t id_b = 0;
	size_t id_out = 0;
	
	for(int i = 0; i < LEN_A*LEN_B*ATT+1; i++) {
		OUTPUT_db[i] = 0;//-1;
	}
	
	for(int i = 0; i < LEN_A; i++) {
		for(int j = 0; j < LEN_B; j++) {
			if(a[i*ATT_A] == b[j*ATT_B]) {
				OUTPUT_db[id_out*ATT] = a[i*ATT_A];
				OUTPUT_db[id_out*ATT+1] = a[i*ATT_A+1];
				OUTPUT_db[id_out*ATT+2] = b[j*ATT_B+1];
				id_out++;
			}
		}
	}
	
	return id_out;
}

size_t cross_join_trivial(DT *OUTPUT_db, DT *a, DT *b) {
	size_t id_a = 0;
	size_t id_b = 0;
	size_t id_out = 0;
	
	for(int i = 0; i < LEN_A*LEN_B*ATT+1; i++) {
		OUTPUT_db[i] = 0;//-1;
	}
	
	for(int i = 0; i < LEN_A; i++) {
		for(int j = 0; j < LEN_B; j++) {			
			if(a[i*ATT_A] == b[j*ATT_B]) {
				id_out++;
				OUTPUT_db[(i*LEN_B+j)*ATT] = a[i*ATT_A];
				OUTPUT_db[(i*LEN_B+j)*ATT+1] = a[i*ATT_A+1];
				OUTPUT_db[(i*LEN_B+j)*ATT+2] = b[j*ATT_B+1];
			}
		}
	}
	
	return id_out;
}


/*int join(DT *OUTPUT_db, DT *a, DT *b, unsigned len_a, unsigned len_b, unsigned att_a, unsigned att_b) {
	int id_a = 0;
	int id_b = 0;
	int id_out = 0;
	int att_out = att_a + att_b - 1;
	for(int i = 0; i < len_a + len_b && id_a < len_a && id_b < len_b; i++) {
		if(a[id_a] == b[id_b]) { // Compare first element
			OUTPUT_db[id_out*att_out] = a[id_a*att_a];
			OUTPUT_db[id_out*att_out+1] = a[id_a*att_a+1];
			OUTPUT_db[id_out*att_out+2] = b[id_b*att_b+1];
			//memcpy(OUTPUT_db + id_out * att_out, a+id_x*att_a, att_a);
			//memcpy(OUTPUT_db + id_out * att_out + att_a, a+id_x*att_a, att_a);
			id_a++;
			id_b++;
			id_out++;
		} else if (id_a > id_b) {
			id_b++;
		} else {
			id_a++;
		}
	}
	return id_out;
} */


DT agg_mean_tree(DT *db, unsigned len, unsigned att) {
	DT sum[len];
	for(int i = 0; i < len; i++) {
		sum[i] = db[i*att+1] + db[i*att+2];
	}
	DT mean = sum_tree(sum, len, 1);
	unsigned joined = db[len*att];
	if(joined > 0) {
		return mean/joined;
	} else {
		return 0;
	}
}

DT agg_mean(DT *db, unsigned len, unsigned att) {
	DT sum[len];
	for(int i = 0; i < len; i++) {
		sum[i] = db[i*att+1] + db[i*att+2];
	}
	return mean_with_abort(sum, len);
}

Output mpc_main(InputA INPUT_A, InputB INPUT_B) {
	Output res;
	
	DT db[LEN_A*LEN_B*ATT+1]; // +1 is an ugly hack to copy len into buffer
	
	// merge databases
	res.joined = cross_join(db, INPUT_A.db, INPUT_B.db);
	
	if(res.joined >= LEN_A*LEN_B) { // Limits the last element
			res.joined = LEN_A*LEN_B-1;
	}
	db[LEN_A*LEN_B*ATT] = res.joined;
	res.analysis1 = agg_mean_tree(db, LEN_A*LEN_B, ATT);
	res.analysis2 = res.analysis1;
	//res.analysis2 = variance(db, LEN_A*LEN_B);
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
		//a.db[i*ATT_A] = i*10+rand()%8;
		a.db[i*ATT_A] = rand()%20;
		a.db[i*ATT_A+1] = rand()%100;
	}
	for(int i = 0; i < LEN_B; i++) {
		b.db[i*ATT_B] = i*10+rand()%8;
		b.db[i*ATT_B+1] = rand()%100;
	}
	Output res = mpc_main(a, b);
	
	printf("Output N=%d mean=%d variance=%d\n", res.joined, res.analysis1, res.analysis2);
	return 0;
}
#endif
