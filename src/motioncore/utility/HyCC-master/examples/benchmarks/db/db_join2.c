/**
 * Example on how to merge two data sets and to perform various analyses
 */
 
#include <string.h>
#include <stdio.h>



#define LEN_A 30
#define LEN_B 30

#define ATT_A 2 //Number of attributes
#define ATT_B 2


#include "db.h"


size_t cross_join_trivial(DT *OUTPUT_db, DT *a, DT *b) {
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

// DB[len][att] row[att]
size_t cross_join_inner(DT *OUTPUT_db, DT *db, DT *row, unsigned len, unsigned att) {
	size_t id_out = 0;
	
	unsigned att_out = att*2-1;
	
	for(int i = 0; i < len*att_out; i++) {
		OUTPUT_db[i] = 0;
	}
	
	for(int i = 0; i < len; i++) {			
		if(db[i*att] == row[0]) {
			id_out++;
			OUTPUT_db[i*att_out] = db[i*att];
			OUTPUT_db[i*att_out+1] = db[i*att+1];
			OUTPUT_db[i*att_out+2] = row[1];
		}
	}
	return id_out;
}

size_t cross_join_decomposed(DT *OUTPUT_db, DT *a, DT *b) {
	size_t id_out = 0;
	
	DT zero[LEN_B*ATT];
	for(int i = 0; i < LEN_B*ATT; i++) {
		zero[i] = 0;
	}
	for(int i = 0; i < LEN_A; i++) {
		OUTPUT_db[i] = 0;//-1;
		memcpy(&OUTPUT_db[i*LEN_B*ATT], zero, LEN_B*ATT*sizeof(DT));
	}
	
	for(int i = 0; i < LEN_A; i++) {
		DT row[ATT_B];
		row[0] = a[i*ATT_A];
		row[1] = a[i*ATT_A+1];
		DT tmp[LEN_B*ATT];
		id_out += cross_join_inner(tmp, b, row, LEN_B, ATT_B);
		memcpy(OUTPUT_db, tmp, LEN_B*ATT*sizeof(DT));
		id_out += tmp[LEN_B+ATT];
	}
	OUTPUT_db[LEN_A*LEN_B*ATT] = id_out;
	return id_out;
}


DT sqr(DT val, DT exp) {
	DT dist = (val - exp) * (val - exp);
	return dist;
}

DT agg_variance(DT *db, unsigned len, unsigned att) {
	DT exp = mean(db, len);
	DT var[len];// = 0;
	for(int i = 0; i < len; i++) {
		if(db[i]!=0) {
			var[i] = sqr(db[i], exp);
		} else {
			var[i] = 0;
		}
	}
	unsigned joined = db[len*att];
	DT res = sum_tree(var, len, 1);
	return res / joined;
}

DT agg_variance_sum(DT *db, unsigned len, unsigned att) {
	DT exp = mean(db, len);
	DT var[len];// = 0;
	for(int i = 0; i < len; i++) {
		if(db[i]!=0) {
			var[i] = sqr(db[i], exp);
		} else {
			var[i] = 0;
		}
	}
	DT res = sum_tree(var, len, 1);
	return res;
}

DT agg_variance_decomposed(DT *db, unsigned len, unsigned att) {
	DT tmp[LEN_B*att];
	DT sum[LEN_A];
	for(int i = 0; i < LEN_A; i++) {
		memcpy(tmp, &db[i*LEN_B*att],LEN_B*att*sizeof(DT));
		sum[i] = agg_variance_sum(tmp, LEN_B, att);
	}
	DT var = sum_tree(sum, LEN_A, 1);
	unsigned joined = db[len*att];
	if(joined > 0) {
		return var/joined;
	} else {
		return 0;
	}
}


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

DT agg_sum_tree(DT *db, unsigned len, unsigned att) {
	DT sum[len];
	for(int i = 0; i < len; i++) {
		sum[i] = db[i*att+1] + db[i*att+2];
	}
	DT res = sum_tree(sum, len, 1);
	return res;
}

DT agg_mean_decomposed(DT *db, unsigned len, unsigned att) {
	DT tmp[LEN_B*att];
	DT sum[LEN_A];
	for(int i = 0; i < LEN_A; i++) {
		memcpy(tmp, &db[i*LEN_B*att],LEN_B*att*sizeof(DT));
		sum[i] = agg_sum_tree(tmp, LEN_B, att);
	}
	DT mean = sum_tree(sum, LEN_A, 1);
	unsigned joined = db[len*att];
	if(joined > 0) {
		return mean/joined;
	} else {
		return 0;
	}
}


/*DT agg_mean(DT *db, unsigned len, unsigned att) {
	DT sum[len];
	for(int i = 0; i < len; i++) {
		sum[i] = db[i*att+1] + db[i*att+2];
	}
	return mean_with_abort(sum, len);
}*/

Output mpc_main(InputA INPUT_A, InputB INPUT_B) {
	Output res;
	
	DT db[LEN_A*LEN_B*ATT+1]; // +1 is an ugly hack to copy len into buffer
	
	// merge databases
	res.joined = cross_join_decomposed(db, INPUT_A.db, INPUT_B.db);
	
	if(res.joined >= LEN_A*LEN_B) { // Limits the last element
			res.joined = LEN_A*LEN_B-1;
	}
	db[LEN_A*LEN_B*ATT] = res.joined;
	res.analysis1 = agg_mean_decomposed(db, LEN_A*LEN_B, ATT);
	res.analysis2 = agg_variance_decomposed(db, LEN_A*LEN_B, ATT);
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
