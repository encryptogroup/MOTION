/* Neural Network according to Figure 12 of MiniONN 
	Assumes image to be square, assume window size to be odd
*/
#include <stdio.h>
#include <string.h>

typedef unsigned DT;

void DT_memset(DT* OUTPUT_res, int len, DT val) {
	for(int i = 0; i < len; i++) {
		OUTPUT_res[i] = val;
	}
}



void convolution_naive(DT *image, DT* kernel, DT* OUTPUT_layer, unsigned image_width, unsigned window_size, unsigned stride, unsigned conv_width)
{
	unsigned window_unrolled = window_size * window_size;
	// Need to assign each input pixel to the convolution matrix
	unsigned x, y, wx, wy;
	for(y = 0; y < conv_width; y++) { // Inner position in the image
		for(x = 0; x < conv_width; x++) {
			unsigned oPos = x+y*conv_width;
			DT tmp = 0;
			for(wy = 0; wy < window_size; wy++) {
				for(wx = 0; wx < window_size; wx++) {
					unsigned convPos = wx+wy*window_size;
					tmp += kernel[convPos] * image[(y*stride + wy) * image_width + (x*stride + wx)];
				}				
			}
			OUTPUT_layer[oPos] = tmp;
		}
	}
}


void convolution_naive_outputs(DT *image, DT* kernels, DT* OUTPUT_layer, unsigned image_width, unsigned window_size, unsigned output_size, unsigned stride, unsigned conv_width) {	
	//unsigned res[conv_width*conv_width*];
	//DT_memset(OUTPUT_layer, conv_width*conv_width*output_size, 0);
	unsigned kernel_size = window_size*window_size;
	for(unsigned o = 0; o < output_size; o++) {
		DT kernel[kernel_size];
		DT res[conv_width*conv_width];
		memcpy(kernel, kernels+ o*kernel_size, kernel_size * sizeof(DT));
		convolution_naive(image, kernel, res, image_width, window_size, stride, conv_width);
		memcpy(OUTPUT_layer + o*(conv_width*conv_width), res, conv_width*conv_width * sizeof(DT));
	}
}


void mpc_main()
{
	DT INPUT_A_image1[784];
	DT INPUT_A_image2[144];
	DT INPUT_B_kernel1[400];
	DT INPUT_B_kernel2[400];
	DT res1[9216];
	DT res2[1024];

	// Convolution (1)
	//, DT* kernels, DT* OUTPUT_layer, unsigned image_width, unsigned window_size, unsigned output_size, unsigned stride, unsigned conv_width) {	
	convolution_naive_outputs(INPUT_A_image1, INPUT_B_kernel1, res1, 28, 5, 16, 1, 24);
	convolution_naive_outputs(INPUT_A_image2, INPUT_B_kernel2, res2, 12, 5, 16, 1, 8);
	
	DT OUTPUT_sum = res1[0] + res2[1];
	/*for(int i = 0; i < 9216; i++) {
		OUTPUT_sum += res1[];
	}
	for(int i = 0; i < 1024; i++) {
		OUTPUT_sum += res2[i];
	}*/
	
}

/*void main() {
	InputB testB;
	DT_memset(testB.kernelsL1, OUTPUT_CHANNELS * WINDOW_WIDTH * WINDOW_WIDTH, 1); // (1)
	DT_memset(testB.kernelsL2, OUTPUT_CHANNELS * SIZE_KERNELS_2, 1); 
	DT_memset(testB.kernelsFC1, FC_COLS_1 * FULLY_CONNECTED_WIDTH, 3);
	DT_memset(testB.kernelsFC2, FINAL_OUTPUT_CHANNELS * FULLY_CONNECTED_WIDTH, 2); 	

	InputA testA;
	DT_memset(testA.image,1, IMAGE_WIDTH *IMAGE_WIDTH);
	
	Output res = mpc_main(testA, testB);
	printf("Result:");
	for(unsigned i = 0; i < FINAL_OUTPUT_CHANNELS; i++) {
		printf("%d", res.final_layer[i]);
	}
}*/
