#include "fix32.h"

// vodi main(){
void mpc_main() {

  fixedpt INPUT_A_x;
  fixedpt INPUT_B_x;

  fixedpt OUTPUT_mul = fixedpt_sub_overflow_free(INPUT_A_x, INPUT_B_x);
}

