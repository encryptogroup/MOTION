#include "fix64.h"

// vodi main(){
void mpc_main() {
  fixedptd INPUT_A_x;
  fixedptd INPUT_B_x;

  float64 OUTPUT_to_float64 = fixedptd_to_float64(INPUT_A_x, INPUT_B_x);
}
