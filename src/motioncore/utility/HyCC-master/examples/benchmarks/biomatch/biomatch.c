#define N 256
#define K 4 // currently fixed, do not change

#define INNER 64
#define OUTER (N/INNER)

#include <inttypes.h>
#include <string.h>

typedef int32_t int_t;

int_t match_fix(int_t x1, int_t x2,int_t x3, int_t x4, int_t y1, int_t y2, int_t y3, int_t y4) {
  int_t r = 0;
  int i;
  int t1 = (x1-y1);
  int t2 = (x2-y2);
  int t3 = (x3-y3);
  int t4 = (x4-y4);
  r = t1*t1 + t2*t2 + t3*t3 + t4*t4;
  return r;
}

/*int_t match(int_t x[K], int_t y[K]) {
  int_t r = 0;
  int i;
  for(i = 0; i < K; i++) {
    int t = (x[i]-y[i]);
    r+= t*t;
  }
  return r;
}

int_t biomatch_loop() {
  int_t INPUT_A_best_match;
  int_t INPUT_A_db[K];
  int_t INPUT_A_sample[K];
  int_t score = match(INPUT_A_db, INPUT_A_sample);
  int_t best_match = INPUT_A_best_match ^ 0;
  if(score < best_match) {
    best_match = score;
  }
  int_t OUTPUT_res = best_match;
  return OUTPUT_res;
}*/

/*void main() {
  int_t INPUT_A_db[N][K];
  int_t INPUT_B_sample[K];

  int_t best_match = match(INPUT_A_db[0], INPUT_B_sample);;

  int i;
  for(i = 1; i < N; i++) {
    int_t res = match(INPUT_A_db[i], INPUT_B_sample);
    if(res < best_match) {
      best_match = res;
    }
  }

  int_t OUTPUT_res = best_match;
}

void main_decomposed_1() {
  int_t INPUT_A_db[N][K];
  int_t INPUT_B_sample[K];
  int_t matches[N];

  // Compute distances
  for(int i = 0; i < N; i++) {
    matches[i] = match(INPUT_A_db[i], INPUT_B_sample);
  }

  // Compute minimum
  int_t best_match = matches[0];
  for(int i = 1; i < N; i++) {
    if(matches[i] < best_match) {
      best_match = matches[i];
    }
  }


  int_t OUTPUT_res = best_match;

}*/


/*int_t min(int_t *data, int len) {
  int_t best_match = data[0];
  for(int i = 1; i < N; i++) {
    if(data[i] < best_match) {
      best_match = data[i];
    }
  }
  return best_match;
}*/

int_t min(int_t *data, int len, int stride) {
	if(stride > len) {
		return data[0];
	} else {
		for(int i = 0; i + stride < len; i+=stride<<1) {
			if(data[i+stride] < data[i]) {
				data[i] = data[i+stride];
			}

		}
		return min(data, len, stride<<1);
	}
}

int_t min_decomposed(int_t *data, int len) {
	int_t outer_min[OUTER];
	for(int i = 0; i < OUTER; i++) {
		int_t inner_min[INNER];
		memcpy(inner_min, &data[i*INNER], INNER*sizeof(int_t));
		outer_min[i] = min(inner_min, INNER, 1);
	}
	return min(outer_min, OUTER, 1);
}

/*int_t match_min(int_t *db, unsigned len, int_t *sample) {
  int_t matches[len];

  // Compute distances
  for(int i = 0; i < len; i++) {
    matches[i] = match_fix(db[i*K], db[i*K+1], db[i*K+2], db[i*K+3], sample[0], sample[1], sample[2], sample[3]);
  }
  // Compute minimum
  int_t best_match = min(matches, len, 1);
  return best_match;
}*/

void match_decomposed(int_t *db, int_t *OUTPUT_matches, unsigned len, int_t *sample) {

  // Compute distances
  for(int i = 0; i < len; i++) {
    OUTPUT_matches[i] = match_fix(db[i*K], db[i*K+1], db[i*K+2], db[i*K+3], sample[0], sample[1], sample[2], sample[3]);
  }
  // Compute minimum
}

void mpc_main() {
	int_t INPUT_A_db[N*K];
  int_t INPUT_B_sample[K];
  //int_t matches[OUTER];
  int_t matches[N];


	int_t matches_inner[INNER];
  for(int i = 0; i < INNER; i++) {
		matches_inner[i]=0;
	}
  // Compute distances
  for(int i = 0; i < OUTER; i++) {
		int_t db_inner[INNER*K];

		memcpy(db_inner, &INPUT_A_db[i*INNER*K], INNER*K*sizeof(int_t));
		match_decomposed(db_inner, matches_inner, INNER, INPUT_B_sample);
		memcpy(&matches[i*INNER], matches_inner, INNER*sizeof(int_t));
  }
  // Compute minimum
  int_t best_match = min_decomposed(matches, N);
  int_t OUTPUT_res = best_match;
}


/*void mpc_main() {
  int_t INPUT_A_db[N][K];
  int_t INPUT_B_sample[K];
  int_t matches[N];

  // Compute distances
  for(int i = 0; i < N; i++) {
    matches[i] = match_fix(INPUT_A_db[i][0], INPUT_A_db[i][1], INPUT_A_db[i][2], INPUT_A_db[i][3], INPUT_B_sample[0], INPUT_B_sample[1], INPUT_B_sample[2], INPUT_B_sample[3]);
  }
  // Compute minimum
  int_t best_match = min(matches, N,1);
  int_t OUTPUT_res = best_match;
}*/
