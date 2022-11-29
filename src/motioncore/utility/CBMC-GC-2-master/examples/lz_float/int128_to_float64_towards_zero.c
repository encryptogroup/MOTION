#include "float64.h"

// vodi main(){
void mpc_main() {
  __uint128_t INPUT_A_x;
  __uint128_t INPUT_B_x;

  float64 OUTPUT_float32 = int128_to_float64_towards_zero(INPUT_A_x, INPUT_B_x);
}
