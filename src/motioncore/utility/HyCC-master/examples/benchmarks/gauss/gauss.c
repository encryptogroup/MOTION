#define N 3

#include <stdio.h>
#include <string.h>

#define FP
#ifdef FP
	#include "fixpoint.h"
	typedef fixedpt DT;
#else
	typedef int DT;
#endif



typedef struct
{
	DT m[N*N]; // (1)
} InputMatrix;

typedef struct
{
	DT b[N]; // (1)
} InputVector;

typedef struct
{
	DT res[N];
} Output;


DT abs(DT val) {
	if(val < 0) {
		return -val;
	} else {
		return val;
	}
}

void identity(DT* OUTPUT_m) {
	for(int i = 0; i<N; i++) {
		for(int j = 0; j<N; j++) {
			if(i==j) {
				OUTPUT_m[i*N+j] = 1;
			 } else{
				OUTPUT_m[i*N+j] = 0; 
			 }	
		}
	}
	//return I;
}

/*void printVector(InputVector v) {
	for(int i =0; i < N; i++) {
			//printf("%f ", v.b[i]);
			printf("%d ", v.b[i]);
	}
	printf("\n");
}

void printMatrix(InputMatrix m) {
	for(int i =0; i < N; i++) {
		for(int j = 0; j < N; j++) {
			printf("%d ", m.m[i*N+j]);
		}
		printf("\n");
	}
	printf("\n");
}

void printBoth(InputMatrix m, InputVector v) {
	for(int i =0; i < N; i++) {
		for(int j = 0; j < N; j++) {
			printf("%d ", m.m[i*N+j]);
		}
		printf("| %d ", v.b[i]);
		printf("\n");
	}
	printf("\n");
}*/

/**
 * Recomputes the result once LU decomposition is completed
 */
void solve_backtracking(DT *m, DT *b, DT *OUTPUT_res) {
#ifdef FP
	for(int i = 0; i < N;i++) {
		OUTPUT_res[i] = 0;
	}
	OUTPUT_res[N-1]= fixedpt_div(b[N-1], m[N*N-1]);
	for(int i = N-2; i >=0; i--) {
		DT tmp = 0;
		for(int j = i+1; j < N; j++) {
			tmp += fixedpt_mul(OUTPUT_res[j], m[i*N+j]);
			//tmp += ((fixedptd)OUTPUT_res[j] * (fixedptd)m[i*N+j]) >> (fixedptd)FIXEDPOINT_FRACTION_BITS;
		}
		//OUTPUT_res[i] = fixedpt_div((b[i] - tmp), m[i*N+i]);
		OUTPUT_res[i] = ((fixedptd)(b[i] - tmp) << (fixedptd)FIXEDPOINT_FRACTION_BITS) / (fixedptd)m[i*N+i];
	}	
#else	
	OUTPUT_res[N-1]= b[N-1]/m[(N-1)*N+N-1];
	for(int i = N-2; i >=0; i--) {
		DT tmp = 0;
		for(int j = i+1; j < N; j++) {
			tmp += OUTPUT_res[j]*m[i*N+j];
		}
		OUTPUT_res[i] = (b[i] - tmp) / m[i*N+i];
	}
#endif	
}

/**
 *  Swap, assuming LU decomposition
 */
/*void swap(DT* OUTPUT_m, DT* OUTPUT_v, int n, int from, int to) {
	if(from!=to) {
		// Iterate over columns)
		for(int j = from; j < n; j++) {
			DT tmp = OUTPUT_m[from*n+j];
			OUTPUT_m[from*n+j] = OUTPUT_m[to*n+j];
			OUTPUT_m[to*n+j] = tmp;
		}
		DT tmp = OUTPUT_v[from];
		OUTPUT_v[from] = OUTPUT_v[to];
		OUTPUT_v[to] = tmp;
	}
	//memcpy(OUTPUT_m, m, N*N*sizeof(DT));
	//memcpy(OUTPUT_v, v, N*sizeof(DT));
}*/

void swap(DT* m, DT* v, DT* OUTPUT_m, DT* OUTPUT_v, int n, int from, int to) {
	if(from!=to) {
		// Iterate over columns)
		for(int j = from; j < n; j++) {
			DT tmp = m[from*n+j];
			m[from*n+j] = m[to*n+j];
			m[to*n+j] = tmp;
		}
		DT tmp = v[from];
		v[from] = v[to];
		v[to] = tmp;
	}
	memcpy(OUTPUT_m, m, N*N*sizeof(DT));
	memcpy(OUTPUT_v, v, N*sizeof(DT));
}

/**
 * Performs the propagating swap for LU decomposition
 */
void pivot_swap(DT *m, DT *b, DT *OUTPUT_m, DT *OUTPUT_b, int i, int n) {
	memcpy(OUTPUT_m, m, sizeof(DT)*N*N);
	memcpy(OUTPUT_b, b, sizeof(DT)*N);
	for(int k=i+1; k < n; k++) {
		if(m[k*n+i] > m[i*n+i]) {
			swap(m, b, OUTPUT_m, OUTPUT_b, n, i, k);
			memcpy(m, OUTPUT_m, sizeof(DT)*N*N);
			memcpy(b, OUTPUT_b, sizeof(DT)*N);
		}
	}
	//memcpy(OUTPUT_m, m, sizeof(DT)*N*N);
	//memcpy(OUTPUT_b, b, sizeof(DT)*N);
}


/**
 *  Simple Guassian, no pivoting. 
 */
/*Output gaussj_A(InputMatrix a, InputVector b) {
	InputMatrix L = identity();

	// n-1 Iterationsschritte
	for(int i= 0; i < N-1; i++) {
		// Zeilen der Restmatrix werden durchlaufen
		for(int k=i+1; k < N; k++) {
			//L(k,i) := R(k,i) / R(i,i) // Achtung: vorher Prüfung auf Nullwerte notwendig
			L.m[k*N+i] = a.m[k*N+i] / a.m[i*N+i];
			// Spalten der Restmatrix werden durchlaufen
			for(int j = i; j < N; j++) {
				// Berechnung von R
				// R(k,j) := R(k,j) - L(k,i) * R(i,j)
				a.m[k*N+j] = a.m[k*N+j] - L.m[k*N+i] * a.m[i*N+j];
			}
			b.b[k] = b.b[k] - L.m[k*N+i] * b.b[i];
		}
		printBoth(a,b);	
	}
	Output out = solve_backtracking(a.m, b.b);
	return out;
}*/


/**
 *  With Pivoting and one swap for the identified maximum
 */
/*Output gaussj_B(InputMatrix a, InputVector b) {
	printf("Solving the following Equations:\n");
	printBoth(a,b);	
	InputMatrix L = identity();
	
	// Iterations
	for(int i= 0; i < N-1; i++) {
		printf("Iteration %d:\n",i);
		int maxRow = i*N+i;
		DT max = a.m[maxRow];
		// Iterate over rows in remainder
		for(int k=i+1; k < N; k++) {
			if(a.m[k*N+i] > max) {
				max =a.m[k*N+i];
				maxRow = k;
			}
		}
		// Swap
		swap(a.m, b.b, N, i, maxRow);
		
		// Iterate over rows in remainder
		for(int k=i+1; k < N; k++) {
			L.m[k*N+i] = a.m[k*N+i] / a.m[i*N+i]; // TODO need div-zero check
			// Iterates over columns in remainder
			for(int j = i; j < N; j++) {
				// Berechnung von R
				// R(k,j) := R(k,j) - L(k,i) * R(i,j)
				a.m[k*N+j] = a.m[k*N+j] - L.m[k*N+i] * a.m[i*N+j];
			}
			b.b[k] = b.b[k] - L.m[k*N+i] * b.b[i];
		}
		printBoth(a,b);	
	}
	// Output
	Output out = solve_backtracking(a.m, b.b);
	
	return out;
}*/


/**
 *  With Pivoting and a propagation swap
 */
/*Output gaussj_C(InputMatrix a, InputVector b) {
	printf("Solving the following Equations Variant C:\n");
	printBoth(a,b);	
	InputMatrix L = identity();
	// Iterations
	for(int i= 0; i < N-1; i++) {
		printf("Iteration %d:\n",i);
		// Iterate over rows in remainder
		for(int k=i+1; k < N; k++) {
			if(a.m[k*N+i] > a.m[i*N+i]) {
				swap(a.m, b.b, N, i, k);
			}
		}
		
		// Iterate over rows in remainder
		for(int k=i+1; k < N; k++) {
			L.m[k*N+i] = a.m[k*N+i] / a.m[i*N+i]; // TODO need div-zero check
			// Iterates over columns in remainder
			for(int j = i; j < N; j++) {
				// Berechnung von R
				// R(k,j) := R(k,j) - L(k,i) * R(i,j)
				a.m[k*N+j] = a.m[k*N+j] - L.m[k*N+i] * a.m[i*N+j];
			}
			b.b[k] = b.b[k] - L.m[k*N+i] * b.b[i];
		}
		printBoth(a,b);	
	}
	// Output
	Output out = solve_backtracking(a.m, b.b);
	
	return out;
}*/




/**
 *  Guassian with propagating pivot for fix point computations
 */
void gaussj_D(DT *m, DT *b, DT *OUTPUT_res) {
	#ifdef DEBUG		
	printf("Solving the following Equations Variant D:\n");
	printBoth(a,b);	
	#endif
	InputMatrix L;
	identity(L.m);
	// Iterations
	for(int i= 0; i < N-1; i++) {
		#ifdef DEBUG		
		printf("Iteration %d:\n",i);
		#endif
		// Swap
		DT m_tmp[N*N];
		DT b_tmp[N];
		pivot_swap(m, b, m_tmp, b_tmp, i, N);
		memcpy(m, m_tmp, sizeof(DT)*N*N);
		memcpy(b, b_tmp, sizeof(DT)*N);
		
		// Iterate over rows in remainder
		for(int k=i+1; k < N; k++) {
			//L.m[k*N+i] = a.m[k*N+i] / a.m[i*N+i]; // TODO need div-zero check
			L.m[k*N+i] = fixedpt_div(m[k*N+i], m[i*N+i]);
			// Iterates over columns in remainder
			for(int j = i; j < N; j++) {
				// Berechnung von R
				// R(k,j) := R(k,j) - L(k,i) * R(i,j)
				//a.m[k*N+j] = a.m[k*N+j] - L.m[k*N+i] * a.m[i*N+j];
				m[k*N+j] = m[k*N+j] - fixedpt_mul(L.m[k*N+i],m[i*N+j]);
			}
			//b.b[k] = b.b[k] - L.m[k*N+i] * b.b[i];
			b[k] = b[k] - fixedpt_mul(L.m[k*N+i],b[i]);
		}	
		#ifdef DEBUG		
		printBoth(a,b);	
		#endif
	}
	// Output
	solve_backtracking(m, b, OUTPUT_res);
	
	//return out;
}

/**
 *  With Pivoting and active swap
 */
/*Output gaussj_E(InputMatrix a, InputVector b) {
	printf("Solving the following Equations Variant D:\n");
	printBoth(a,b);	
	InputMatrix L = identity();
	// Iterations
	for(int i= 0; i < N-1; i++) {
		printf("Iteration %d:\n",i);
		pivot_swap(a.m, b.b, i, N);
		for(int k=i+1; k < N; k++) {
			L.m[k*N+i] = a.m[k*N+i] / a.m[i*N+i]; // Yao candidate?
			// Arithmetic candidate
			for(int j = i; j < N; j++) {
				a.m[k*N+j] = a.m[k*N+j] - L.m[k*N+i] * a.m[i*N+j];
				//a.m[k*N+j] = a.m[k*N+j] - fixedpt_mul(L.m[k*N+i],a.m[i*N+j]);
			}
			b.b[k] = b.b[k] - L.m[k*N+i] * b.b[i];
		}			
		printBoth(a,b);	
	}
	Output out = solve_backtracking(a.m, b.b);
	
	return out;
}*/

Output mpc_main(InputMatrix INPUT_A_m, InputVector INPUT_B_b) {
	Output OUTPUT_res;
	gaussj_D(INPUT_A_m.m, INPUT_B_b.b, OUTPUT_res.res);
	return OUTPUT_res;
}



/*int main() {
	InputMatrix INPUT_A_m;
	InputVector INPUT_B_b;
	
	// x=2, y=1, z=3
	INPUT_A_m.m[0+0*3] = 2;
	INPUT_A_m.m[1+0*3] = 1;
	INPUT_A_m.m[2+0*3] = 3;
	INPUT_B_b.b[0] = 14;
	INPUT_A_m.m[0+1*3] = 3;
	INPUT_A_m.m[1+1*3] = 7;
	INPUT_A_m.m[2+1*3] = 9;
	INPUT_B_b.b[1] = 40;
	INPUT_A_m.m[0+2*3] = 0;
	INPUT_A_m.m[1+2*3] = 3;
	INPUT_A_m.m[2+2*3] = 1;
	INPUT_B_b.b[2] = 6;
	
#ifdef FP
	for(int i = 0; i < N*N; i++) {
		INPUT_A_m.m[i] <<= FIXEDPOINT_FRACTION_BITS;
	}
	for(int i = 0; i < N; i++) {
		INPUT_B_b.b[i] <<= FIXEDPOINT_FRACTION_BITS;
	}
#endif 	
	
	
	Output OUTPUT_res;
	
	gaussj_D(INPUT_A_m.m, INPUT_B_b.b, OUTPUT_res.res);
	
	printf("Solution: ");
	for(int i =0; i < N; i++) {
#ifdef FP
		printf("(%d) ", OUTPUT_res.res[i]);
		OUTPUT_res.res[i] >>= FIXEDPOINT_FRACTION_BITS;
#endif		
		printf("%d ", OUTPUT_res.res[i]);
	}
	printf("\n");
	return 0;
}*/
