#include "fix64.h"

// vodi main(){
void mpc_main()
{

  fixedptd INPUT_A_x;
  fixedptd INPUT_B_x;

  fixedptd OUTPUT_sqrt_P0132 = fixedptd_sqrt_P0132_overflow(INPUT_A_x, INPUT_B_x);
}
