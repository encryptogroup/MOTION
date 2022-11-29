/* Neural Network according to Figure 12 of MiniONN 
	Assumes image to be square, assume window size to be odd
*/
#include <stdio.h>

typedef unsigned DT;

DT relu(DT val) {
	if(val>0) {
		return val;
	} else {
		return 0;
	}
}

void max_pooling_2(DT *vals, DT *OUTPUT_res, unsigned cols, unsigned rows) {
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

DT mul(DT a, DT b) {
	return a*b; // to be replaced by scaled variant
}



void mmul(DT* a, DT* b, DT *OUTPUT_res, unsigned rows_a, unsigned cols_b, unsigned common) {
	for(unsigned i = 0; i < rows_a; i++) {
		for(unsigned j = 0; j < cols_b; j++) {
			DT sum = 0;
			for(unsigned k = 0; k < common; k++) {
				sum += mul(a[i*common+k], b[k*cols_b+j]);
			}
			OUTPUT_res[i*cols_b+j] = sum;
		}
	}
}


void convolution(DT *image, DT* kernels, DT* OUTPUT_layer, unsigned image_width, unsigned window_size, unsigned output_channels)
{
	// Kernels is combination of multiple kernels, one for each output (size_outputs X kernel), i.e., size_output X size_window X size window

	
//	unsigned crop = image_width - window_size + 1;
	unsigned conv_width = image_width - window_size + 1;
	unsigned conv_cols = conv_width * conv_width;
	unsigned window_unrolled = window_size * window_size;

	// e.g., window_size = 5 ==> window_unrolled = 25
	// image_width = 28 -> conv_width = 24 ==> conv_cols = 576
	// convolution matrix is 25x576
	DT conv[window_unrolled * conv_cols];
	// For output_channels = 16, kernels matrix is 16x25

	// Need to assign each input pixel to the convolution matrix
	unsigned x, y, wx, wy;
	for(x = 0; x < conv_width; x++) { // Inner position in the image
		for(y = 0; y < conv_width; y++) {
			for(wx = 0; wx < window_size; wx++) {
				for(wy = 0; wy < window_size; wy++) {
//					printf("Total: %d, write: %d\n", window_unrolled*conv_cols, (wx+wy*window_size)*conv_cols + (x+(y*conv_width)));
//					printf("Image: %d, read: %d\n", image_width*image_width, (y + wy) * image_width + (x + wx));
					conv[(wx+wy*window_size)*conv_cols + (x+(y*conv_width))]  = image[(y + wy) * image_width + (x + wx)];
					// x and y define column in convolution matrix
					// window position defines row

				}
			}
		}
	}

	// Code that multiplies the matrices;
	
	mmul(kernels, conv, OUTPUT_layer, output_channels, conv_cols, window_unrolled);
}


// Parameters taken from the paper
#define IMAGE_WIDTH 6
#define WINDOW_WIDTH 3
#define STRIDE 1

#define OUTPUT_CHANNELS 2
#define IMAGE_CROP (IMAGE_WIDTH - WINDOW_WIDTH + 1)
#define INTERMEDIATE_SIZE (IMAGE_CROP * IMAGE_CROP)

#define FIRST_LAYER_SIZE ((IMAGE_CROP/2)*(IMAGE_CROP/2)*OUTPUT_CHANNELS)

typedef struct
{
	DT image[IMAGE_WIDTH * IMAGE_WIDTH];
} InputA;


typedef struct
{
	DT kernels[OUTPUT_CHANNELS * WINDOW_WIDTH * WINDOW_WIDTH];
} InputB;

typedef struct
{
	DT first_layer[FIRST_LAYER_SIZE];
} Output;


Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	DT intermediate_layer[OUTPUT_CHANNELS * INTERMEDIATE_SIZE];

	// Convolution (1)
	convolution(INPUT_A.image, INPUT_B.kernels, intermediate_layer, IMAGE_WIDTH, WINDOW_WIDTH, OUTPUT_CHANNELS);

	// Relu (2)
	for(unsigned i = 0; i < OUTPUT_CHANNELS * INTERMEDIATE_SIZE; i++) {
		intermediate_layer[i] = relu(intermediate_layer[i]);
	}

	// Max pooling (3)
	Output output;
	max_pooling_2(intermediate_layer, output.first_layer, OUTPUT_CHANNELS, INTERMEDIATE_SIZE);	
	
	return output;
}

