//#define C 3 // Cluster
//#define N 10 // Data
//#define D 2//

#define D 2 // Dimension (fix)
#define NA 100 // Number of data points from Party A
#define NB 100 // Number of data points from Party B
#define NC 5 // Number of clusters
#define PRECISION 4

#define LEN (NA+NB)
#define LEN_OUTER 10
#define LEN_INNER (LEN/LEN_OUTER)

#include <stdio.h>
#include <string.h>


typedef int coord_t;

typedef struct
{
	coord_t dataA[D*NA];
} InputA;

typedef struct
{
	coord_t dataB[D*NA];
} InputB;

typedef struct
{
	coord_t cluster[D*NC];
} Output;


coord_t dist2(coord_t x1, coord_t y1, coord_t x2, coord_t y2) {
  return (x1-x2) * (x1-x2) + (y1 - y2) * (y1 - y2);
}

/*void iteration(coord_t *data, coord_t *cluster, coord_t *OUTPUT_cluster, unsigned len, unsigned num_cluster) {
	unsigned i, c;	
	coord_t new_cluster[NC*D];
	unsigned bestMap[len];
	
	 // Compute nearest clusters for Data item i
	 // ToDo Min tree
	for(i = 0; i < len; i++) {
	  bestMap[i] = 0;
	  coord_t dx = data[i*D];
	  coord_t dy = data[i*D+1];
	  coord_t best_dist = dist2(cluster[0], cluster[1], dx, dy);
	  for(c = 1; c < num_cluster; c++) {
			coord_t dist = dist2(cluster[D*c], cluster[D*c+1], dx, dy);
			if(dist < best_dist) {
				best_dist = dist;
				bestMap[i] = c;
			}
	  }
	}
	// Recompute cluster Pos

	unsigned count[num_cluster];
	for(c = 0; c < num_cluster; c++) {
	  new_cluster[c*D] = 0;
	  new_cluster[c*D+1] = 0;
	  count[c] = 0;
	}

	for(i = 0; i < len; i++) {
	  unsigned c = bestMap[i];
	  new_cluster[c*D] += data[i*D];
	  new_cluster[c*D+1] += data[i*D+1];
	  count[c]++;
	}
	for(c = 0; c < num_cluster; c++) {  
	  if(count[c] >0 ) {
		new_cluster[c*D] /= count[c];
		new_cluster[c*D+1] /= count[c];
	  }
	}
	for(i = 0; i < num_cluster*D;i++) {
		OUTPUT_cluster[i] = new_cluster[i];
	}
}*/



// Computes minimum in a tree based fashion and associated with aux element
unsigned min_with_aux(coord_t *data, unsigned *aux, int len, int stride) {
	if(stride > len) {
		return aux[0];
	} else {
		for(int i = 0; i + stride < len; i+=stride<<1) {
			if(data[i+stride] < data[i]) {
				data[i] = data[i+stride];
				aux[i] = aux[i+stride];
			}
		}
		return min_with_aux(data, aux, len, stride<<1);
	}
	/*coord_t min = data[0];
	unsigned res = 0;
	for(int i = 1; i < len; i++){
		if(data[i] < min) {
			min = data[i];
			res = i;
		}
	}
	return res;*/
}


#define ADD2(X,A)  A[X] + A[X+1]
#define ADD4(X,A)  ADD2(X,A) + ADD2(X+2,A)
#define ADD8(X,A)  ADD4(X,A) + ADD4(X+4,A)
#define ADD10(X,A)  ADD8(X,A) + ADD2(X+8,A)
#define ADD16(X,A)  ADD8(X,A) + ADD8(X+8,A)
#define ADD32(X,A)  ADD16(X,A) + ADD16(X+16,A)
#define ADD64(X,A)  ADD32(X,A) + ADD32(X+32,A)
#define ADD128(X,A)  ADD64(X,A) + ADD32(X+64,A)


//#define ADD2(X,A)  A[X] + A[X+1]
#define ADD2_2(X,A)  A[X] + A[X+2]
#define ADD4_2(X,A)  ADD2_2(X,A) + ADD2_2(X+4,A)
#define ADD8_2(X,A)  ADD4_2(X,A) + ADD4_2(X+8,A)
#define ADD10_2(X,A)  ADD8_2(X,A) + ADD2_2(X+16,A)
#define ADD16_2(X,A)  ADD8_2(X,A) + ADD8_2(X+16,A)
#define ADD32_2(X,A)  ADD16_2(X,A) + ADD16_2(X+32,A)
#define ADD64_2(X,A)  ADD32_2(X,A) + ADD32_2(X+64,A)


/**
 * Iteration loop unrolled and depth minimized by computing minimum over tree structure
 */ 
void iteration_unrolled_inner_depth(coord_t *data_inner, coord_t *cluster, coord_t *OUTPUT_cluster, unsigned *OUTPUT_count, unsigned len_inner, unsigned num_cluster) {
	unsigned i,c;
	coord_t dist[num_cluster];
	unsigned pos[num_cluster];
	unsigned bestMap_inner[len_inner];
	
	for(c = 0; c < num_cluster; c++) {
		OUTPUT_cluster[c*D] = 0;
		OUTPUT_cluster[c*D+1] = 0;
		OUTPUT_count[c] = 0;
	}	
	
	// Compute nearest clusters for Data item i
	for(i = 0; i < len_inner; i++) {
	  coord_t dx = data_inner[i*D];
	  coord_t dy = data_inner[i*D+1];
  
	  for(c = 0; c < num_cluster; c++) {
			pos[c]=c;
			dist[c] = dist2(cluster[D*c], cluster[D*c+1], dx, dy);
		}
		bestMap_inner[i] = min_with_aux(dist, pos, num_cluster, 1);
		unsigned cc = bestMap_inner[i];
		OUTPUT_cluster[cc*D] += data_inner[i*D];
		OUTPUT_cluster[cc*D+1] += data_inner[i*D+1];
		OUTPUT_count[cc]++;		
	}
}


/**
 * Iteration loop unrolled
 */ 
void iteration_unrolled_inner(coord_t *data_inner, coord_t *cluster, coord_t *OUTPUT_cluster, unsigned *OUTPUT_count, unsigned len_inner, unsigned num_cluster) {
	unsigned i,c;
	unsigned bestMap_inner[len_inner];
	
	// Compute nearest clusters for Data item i
	for(i = 0; i < len_inner; i++) {
	  bestMap_inner[i] = 0;
	  coord_t dx = data_inner[i*D];
	  coord_t dy = data_inner[i*D+1];
	  coord_t best_dist = dist2(cluster[0], cluster[1], dx, dy);
	  for(c = 1; c < num_cluster; c++) {
			coord_t dist = dist2(cluster[D*c], cluster[D*c+1], dx, dy);
			if(dist < best_dist) {
				best_dist = dist;
				bestMap_inner[i] = c;
			}
	  }
	}

	for(c = 0; c < num_cluster; c++) {
		OUTPUT_cluster[c*D] = 0;
		OUTPUT_cluster[c*D+1] = 0;
		OUTPUT_count[c] = 0;
	}	
	
	// Depth: data_inner * addition
	for(i = 0; i < len_inner; i++) {
		unsigned c = bestMap_inner[i];
		OUTPUT_cluster[c*D] += data_inner[i*D];
		OUTPUT_cluster[c*D+1] += data_inner[i*D+1];
		OUTPUT_count[c]++;
	}
}



/**
 * Iteration unrolled outer loop
 */ 
void iteration_unrolled_outer(coord_t *data, coord_t *cluster, coord_t *OUTPUT_cluster) {
	unsigned j, c;	
	unsigned count[NC];
	
	// Set Outer result
	for(c = 0; c < NC; c++) {
		OUTPUT_cluster[c*D] = 0;
		OUTPUT_cluster[c*D+1] = 0;
		count[c] = 0;
	}	
	
	coord_t loop_clusterD1[NC][LEN_OUTER];
	coord_t loop_clusterD2[NC][LEN_OUTER];
	unsigned loop_count[NC][LEN_OUTER];
	
	
	// Compute decomposition
	for(j = 0; j < LEN_OUTER; j++) {
		// Copy data, fasthack for scalability
		size_t data_offset = j*LEN_INNER*D;
		coord_t data_inner[LEN_INNER*D];
		
		memcpy(data_inner, data+data_offset, LEN_INNER*D*sizeof(coord_t));
		coord_t cluster_inner[NC*D];
		unsigned count_inner[NC];
		
		iteration_unrolled_inner_depth(data_inner, cluster, cluster_inner, count_inner, LEN_INNER, NC);

		// Depth: num_cluster Addition
#if (LEN_OUTER == 10) || (LEN_OUTER == 4)
		for(c = 0; c < NC; c++) {
			loop_clusterD1[c][j] = cluster_inner[c*D];
			loop_clusterD2[c][j] = cluster_inner[c*D+1];
			loop_count[c][j] = count_inner[c];
		}
#else
		for(c = 0; c < NC; c++) {
			OUTPUT_cluster[c*D] += cluster_inner[c*D];
			OUTPUT_cluster[c*D+1] += cluster_inner[c*D+1];
			count[c] += count_inner[c];
		}			
#endif
	}
	
#if (LEN_OUTER == 10)
	for(c = 0; c < NC; c++) {
		OUTPUT_cluster[c*D] = ADD10(0,loop_clusterD1[c]);
		OUTPUT_cluster[c*D+1] = ADD10(0,loop_clusterD2[c]);
		count[c] = ADD10(0, loop_count[c]);
	}
#endif	
#if (LEN_OUTER == 4)
	for(c = 0; c < NC; c++) {
		OUTPUT_cluster[c*D] = ADD4(0,loop_clusterD1[c]);
		OUTPUT_cluster[c*D+1] = ADD4(0,loop_clusterD2[c]);
		count[c] = ADD4(0, loop_count[c]);
	}
#endif		

	// Recompute cluster Pos
	// Compute mean
	for(c = 0; c < NC; c++) {  
	  if(count[c] >0 ) {
			OUTPUT_cluster[c*D] /= count[c];
			OUTPUT_cluster[c*D+1] /= count[c];
	  } 
	}
}



void kmeans(coord_t *data, coord_t *OUTPUT_res) {
	unsigned c, p;
	coord_t cluster[NC*D];

	// Assign random start cluster from data
	for(c = 0; c < NC; c++) {
		cluster[c*D] = data[((c+3)%LEN)*D];
		cluster[c*D+1] = data[((c+3)%LEN)*D+1];
	}

	for (p = 0; p < PRECISION; p++) { 
		coord_t new_cluster[NC*D];
		iteration_unrolled_outer(data, cluster, new_cluster);
		//iteration(data, cluster, new_cluster, len, num_cluster);
		
		// We need to copy inputs to outputs
		for( c = 0; c < NC*D; c++) {
			cluster[c] = new_cluster[c];
		}
	}
	for(c = 0; c < NC; c++) {  
		OUTPUT_res[c*D] = cluster[c*D];
		OUTPUT_res[c*D+1] = cluster[c*D+1];
	}
}



Output mpc_main(InputA INPUT_A, InputB INPUT_B) {
	// First we fuse some input data
	// Both parties contribute data
	coord_t data[LEN*D];
	for(int i = 0; i < NA*D; i++) {
		data[i]=INPUT_A.dataA[i];
	}
	unsigned offset = NA*D;
	for(int i = 0; i < NB*D; i++) {
		data[i+offset]=INPUT_B.dataB[i];
	}

	Output output;
	kmeans(data, output.cluster);
	return output;
}


/*int main() {
  coord_t data[] = { 1,1, 2,2, 3,3, 99,103, 110,100, 115,112, 1,105, 2,99, 3,112,5,130 , 11,12, 1,1, 2,2, 3,3, 99,103, 110,100, 115,112, 1,105, 2,99, 3,112,5,130 , 11,12};
  coord_t res[NC*D];
  kmeans(data, res);
  printf("Idenitfied the following clusters:\n");
  for(int i = 0; i < NC; i++) {
    printf("%d %d %d\n", i, res[i*D], res[i*D+1]);
  }
  return 0;
}*/
