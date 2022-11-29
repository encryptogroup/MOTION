#include "fix64.h"

// vodi main(){
void mpc_main() {

  fixedptd INPUT_A_x;
  fixedptd INPUT_B_x;

  fixedptd OUTPUT_mul_overflowfree = fixedptd_mul_overflowfree(INPUT_A_x, INPUT_B_x);
}

