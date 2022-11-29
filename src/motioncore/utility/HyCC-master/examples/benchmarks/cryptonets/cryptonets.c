/* Neural Network according to Figure 11 of MiniONN 
	Assumes image to be square, assume window size to be odd
*/
#include <stdio.h>
#include <string.h>

// Parameters taken from the paper
#define IMAGE_WIDTH 28 // 28
#define WINDOW_WIDTH 5
#define STRIDE 2
#define OUTPUT_CHANNELS 5 // 5

#define IMAGE_CROP 13 // 13 with padding
#define SIZE_CONVOLUTION (IMAGE_CROP * IMAGE_CROP) // 169

#define FULLY_CONNECTED_WIDTH 100 // (7, 9)
#define FINAL_OUTPUT_CHANNELS 10

typedef unsigned DT;

DT relu(DT val) {
	if(val>0) {
		return val;
	} else {
		return 0;
	}
}


DT activate_sqr(DT val) {
	DT res = val*val;
	return res;
}

void max_pooling(DT *vals, DT *OUTPUT_res, unsigned cols, unsigned rows) {
	unsigned rows_res = rows / 2;
	unsigned cols_res = cols / 2;
	for(unsigned i = 0; i < rows_res; i++) {
		for(unsigned j = 0; j < cols_res; j++) {
			unsigned x = j * 2;
			unsigned y = i * 2;
			DT max = vals[y*cols + x];
			if(vals[y*cols + x + 1] > max) {
				max = vals[y*cols + x + 1];
			}
			if(vals[(y + 1) *cols + x] > max) {
				max = vals[(y + 1) * cols + x];
			} 
			if(vals[(y + 1) *cols + x + 1] > max) {
				max = vals[(y + 1) * cols + x + 1];
			} 
			OUTPUT_res[i * cols_res + j] = max;
		}
	}
}

void max_pooling_outputs(DT *vals, DT *OUTPUT_res, unsigned outputs, unsigned cols, unsigned rows) {
	for(int o = 0; o < outputs; o++) {
		unsigned size = cols*rows; 
		DT input_layer[size]; // We copy data, because compiler is unable to slice array efficiently
		for(int i = 0; i < size; i++) {
			input_layer[i] = vals[o*size+i];
		}
		unsigned output_size = cols/2*rows/2;
		DT res_layer[output_size];
		max_pooling(input_layer, res_layer, cols, rows);
		for(int i = 0; i < output_size; i++) {
			OUTPUT_res[o*output_size+i] = res_layer[i];
		}
	}
}

// FULLY_CONNECTED_WIDTH * SIZE_CONVOLUTION * OUTPUT_CHANNELS = 100*169*5

// rows_a=100, cols_b = 1, common = 5*169

// mmul(INPUT_B.pool_layer, convolution_layer, im_layer, FULLY_CONNECTED_WIDTH, 1, OUTPUT_CHANNELS * SIZE_CONVOLUTION); 
 // 	mmul(INPUT_B.fc[100*10], im_layer[100], final_layer[10], FINAL_OUTPUT_CHANNELS=10, 1, FULLY_CONNECTED_WIDTH=100);
/*void mmul(DT* a, DT* b, DT *OUTPUT_res, unsigned rows_a, unsigned cols_b, unsigned common) {
	for(unsigned i = 0; i < rows_a; i++) {
		for(unsigned j = 0; j < cols_b; j++) {
			DT sum = 0;
			for(unsigned k = 0; k < common; k++) {
				sum += a[i*common+k] * b[k*cols_b+j];
			}
			OUTPUT_res[i*cols_b+j] = sum;
		}
	}
}*/
DT mmulT_unrolled_inner(DT* a, DT* b, unsigned common) { 
	DT sum = 0;
	
	int i = 0;
	// Add the first as groups of eight
	while(i+8<= common) {
		sum += a[i+0]*b[i+0] + a[i+1]*b[i+1] + a[i+2]*b[i+2] + a[i+3]*b[i+3] + a[i+4]*b[i+4] + a[i+5]*b[i+5] + a[i+6]*b[i+6] + a[i+7]*b[i+7];
		i+=8;
	}
	if(i+4<=common) {
		sum += a[i+0]*b[i+0] + a[i+1]*b[i+1] + a[i+2]*b[i+2] + a[i+3]*b[i+3];
		i+=4;
	}
	for(i; i < common; i++) {
		sum += a[i] * b[i];
	}
	
	/*for(unsigned k = 0; k < common; k++) {
		sum += a[k] * b[k];
	}*/
	return sum;
}


void mmulT_unrolled(DT* a, DT* b, DT *OUTPUT_res, unsigned cols_a, unsigned cols_b, unsigned common) {
	for(unsigned i = 0; i < cols_a; i++) {
		DT aRow[common];
		memcpy(aRow, a+i*common, common*sizeof(DT));
		for(unsigned j = 0; j < cols_b; j++) {
			DT bRow[common];
			memcpy(bRow, b+j*common, common*sizeof(DT));
			OUTPUT_res[i*cols_b+j] = mmulT_unrolled_inner(aRow, bRow,common);
		}
	}
}


void convolution_naive(DT *image, DT* kernel, DT* OUTPUT_layer, unsigned image_width, unsigned window_size, unsigned stride, unsigned conv_width)
{
	unsigned window_unrolled = window_size * window_size;
	// Need to assign each input pixel to the convolution matrix
	unsigned x, y, wx=0, wy;
	for(y = 0; y < conv_width; y++) { // Inner position in the image
		for(x = 0; x < conv_width; x++) {
			unsigned oPos = x+y*conv_width;
			DT tmp = 0;
			for(wy = 0; wy < window_size; wy++) {
				#if WINDOW_WIDTH==5
						unsigned convPos = wx+wy*window_size;
						tmp += kernel[convPos] * image[(y*stride + wy) * image_width + (x*stride + 0)] + kernel[convPos] * image[(y*stride + wy) * image_width + (x*stride + 1)] + kernel[convPos] * image[(y*stride + wy) * image_width + (x*stride + 2)] + kernel[convPos] * image[(y*stride + wy) * image_width + (x*stride + 3)] + kernel[convPos] * image[(y*stride + wy) * image_width + (x*stride + 4)];
				#else 
				for(wx = 0; wx < window_size; wx++) {
					unsigned convPos = wx+wy*window_size;
					tmp += kernel[convPos] * image[(y*stride + wy) * image_width + (x*stride + wx)];
				}
				#endif
			/*	for(wx = 0; wx < window_size; wx++) {
					unsigned convPos = wx+wy*window_size;
					tmp += kernel[convPos] * image[(y*stride + wy) * image_width + (x*stride + wx)];
				}				*/
			}
			OUTPUT_layer[oPos] = tmp;
		}
	}
}


void convolution_naive_outputs(DT *image, DT* kernels, DT* OUTPUT_layer, unsigned image_width, unsigned window_size, unsigned output_size, unsigned stride, unsigned conv_width) {	
	//unsigned res[conv_width*conv_width*];
	unsigned kernel_size = window_size*window_size;
	for(unsigned o = 0; o < output_size; o++) {
		DT kernel[kernel_size];
		DT res[conv_width*conv_width];
		memcpy(kernel, kernels+o*kernel_size, kernel_size* sizeof(DT));
		convolution_naive(image, kernel, res, image_width, window_size, stride, conv_width);
		memcpy(OUTPUT_layer + o*(conv_width*conv_width), res, conv_width*conv_width * sizeof(DT));
	}
}

/*void convolution_naive_outputs(DT *image, DT* kernels, DT* OUTPUT_layer, unsigned image_width, unsigned window_size, unsigned output_size, unsigned stride, unsigned conv_width) {	
	//unsigned res[conv_width*conv_width*];
	unsigned kernel_size = window_size*window_size;
	for(unsigned o = 0; o < output_size; o++) {
		DT kernel[kernel_size];
		DT res[conv_width*conv_width];
		for(unsigned i = 0; i < kernel_size; i++) {
			kernel[i] = kernels[o*kernel_size+i];
		}
		convolution_naive(image, kernel, res, image_width, window_size, stride, conv_width);
		for(unsigned i = 0; i < conv_width*conv_width; i++) {
			OUTPUT_layer[o*(conv_width*conv_width) + i] = res[i];
		}
	}
}*/





typedef struct 
{
	DT image[IMAGE_WIDTH * IMAGE_WIDTH];
} InputA;


typedef struct
{
	DT kernelsL1[OUTPUT_CHANNELS * WINDOW_WIDTH * WINDOW_WIDTH]; // (1)
	DT pool_layer[FULLY_CONNECTED_WIDTH * SIZE_CONVOLUTION * OUTPUT_CHANNELS];
	DT fc[FINAL_OUTPUT_CHANNELS * FULLY_CONNECTED_WIDTH];
} InputB;

typedef struct
{
	DT final_layer[FINAL_OUTPUT_CHANNELS];
} Output;



Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	Output OUTPUT_classify;		
	
	// Two lines of padding 
	unsigned padded_width = IMAGE_WIDTH+2;
	DT convolution_input[padded_width*padded_width];
	for(int i = 0; i < padded_width; i++) {
		convolution_input[i] = 0;
		convolution_input[i+padded_width] = 0;
		convolution_input[padded_width*i] = 0;
		convolution_input[padded_width*i+1] = 0;
	} 
	for(int y = 0; y < IMAGE_WIDTH; y++) {
		for(int x = 0; x < IMAGE_WIDTH; x++) {
			convolution_input[(y+2)*padded_width+(x+2)] = INPUT_A.image[y*IMAGE_WIDTH+x];
		}
	}

	// Convolution (1)
	DT convolution_layer[OUTPUT_CHANNELS * SIZE_CONVOLUTION];
	convolution_naive_outputs(convolution_input, INPUT_B.kernelsL1, convolution_layer, padded_width, WINDOW_WIDTH, OUTPUT_CHANNELS, STRIDE, IMAGE_CROP);
	
	
	// Activation Function (2)
	for(unsigned i = 0; i < OUTPUT_CHANNELS * SIZE_CONVOLUTION; i++) {
		convolution_layer[i] = activate_sqr(convolution_layer[i]);
	}
	
	// Combination of Mean pooling and Fully connected (3)
	DT im_layer[FULLY_CONNECTED_WIDTH];	
	mmulT_unrolled(INPUT_B.pool_layer, convolution_layer, im_layer, FULLY_CONNECTED_WIDTH, 1, OUTPUT_CHANNELS * SIZE_CONVOLUTION);

	// Activation Function (4)
	for(unsigned i = 0; i < FULLY_CONNECTED_WIDTH; i++) {
		im_layer[i] = activate_sqr(im_layer[i]);
	}

	// Fully Connected (5)
	DT final_layer[FINAL_OUTPUT_CHANNELS];
	mmulT_unrolled(INPUT_B.fc, im_layer, final_layer, FINAL_OUTPUT_CHANNELS, 1, FULLY_CONNECTED_WIDTH);
	
	for(unsigned i = 0; i < FINAL_OUTPUT_CHANNELS; i++) {
		OUTPUT_classify.final_layer[i] = final_layer[i];
	}
	return OUTPUT_classify;
}


/*
void test(InputA *pINPUT_A, InputB *pINPUT_B, Output *res)
{
	InputA INPUT_A; 
	
	memcpy(INPUT_A.image, pINPUT_A->image, IMAGE_WIDTH*IMAGE_WIDTH*sizeof(DT));
	InputB INPUT_B; 
	memcpy(INPUT_B.kernelsL1, pINPUT_B->kernelsL1, OUTPUT_CHANNELS * WINDOW_WIDTH * WINDOW_WIDTH*sizeof(DT));
	memcpy(INPUT_B.pool_layer, pINPUT_B->pool_layer, FULLY_CONNECTED_WIDTH * SIZE_CONVOLUTION * OUTPUT_CHANNELS*sizeof(DT));
	memcpy(INPUT_B.fc, pINPUT_B->fc, FINAL_OUTPUT_CHANNELS * FULLY_CONNECTED_WIDTH*sizeof(DT));

	Output OUTPUT_classify;		
	// Padding upper left
	unsigned padded_width = IMAGE_WIDTH+2;
	DT convolution_input[padded_width*padded_width];
	for(int i = 0; i < padded_width; i++) {
		convolution_input[i] = 0;
		convolution_input[i+padded_width] = 0;
		convolution_input[padded_width*i] = 0;
		convolution_input[padded_width*i+1] = 0;
	} 
	for(int y = 0; y < IMAGE_WIDTH; y++) {
		for(int x = 0; x < IMAGE_WIDTH; x++) {
			convolution_input[(y+2)*padded_width+(x+2)] = INPUT_A.image[y*IMAGE_WIDTH+x];
		}
	}
	
	// Convolution (1)
	DT convolution_layer[OUTPUT_CHANNELS * SIZE_CONVOLUTION];
	convolution_naive_outputs(convolution_input, INPUT_B.kernelsL1, convolution_layer, padded_width, WINDOW_WIDTH, OUTPUT_CHANNELS, STRIDE, IMAGE_CROP);
	
	
	// Activation Function (2)
	for(unsigned i = 0; i < OUTPUT_CHANNELS * SIZE_CONVOLUTION; i++) {
		convolution_layer[i] = activate_sqr(convolution_layer[i]);
	}
	
	DT im_layer[FULLY_CONNECTED_WIDTH];
	
	mmul(INPUT_B.pool_layer, convolution_layer, im_layer, FULLY_CONNECTED_WIDTH, 1, OUTPUT_CHANNELS * SIZE_CONVOLUTION);

	for(unsigned i = 0; i < FULLY_CONNECTED_WIDTH; i++) {
		im_layer[i] = activate_sqr(im_layer[i]);
	}

	DT final_layer[FINAL_OUTPUT_CHANNELS];
	mmul(INPUT_B.fc, im_layer, final_layer, FINAL_OUTPUT_CHANNELS, 1, FULLY_CONNECTED_WIDTH);

	
	for(unsigned i = 0; i < FINAL_OUTPUT_CHANNELS; i++) {
		res->final_layer[i] = final_layer[i];//OUTPUT_classify.final_layer[i];
	}
}*/

/*void memsetInt(DT *data, DT value, unsigned len) {
	for(unsigned i = 0; i < len;i++) {
		data[i] = value;	
	}
}

int main() {
	InputB testB;
	memsetInt(testB.kernelsL1, 1, OUTPUT_CHANNELS * WINDOW_WIDTH * WINDOW_WIDTH); // (1)
	memsetInt(testB.pool_layer,0, FULLY_CONNECTED_WIDTH * SIZE_CONVOLUTION * OUTPUT_CHANNELS);
	memsetInt(testB.fc,2, FINAL_OUTPUT_CHANNELS * FULLY_CONNECTED_WIDTH);
	InputA testA;
	
	
	memsetInt(testA.image,1, IMAGE_WIDTH *IMAGE_WIDTH);
	
	Output res = mpc_main(testA, testB);
	printf("Result:");
	for(unsigned i = 0; i < FINAL_OUTPUT_CHANNELS; i++) {
		printf("%d", res.final_layer[i]);
	}
}*/
