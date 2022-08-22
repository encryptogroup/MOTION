### Circuit Description
The following circuits are generated with [HyCC](https://gitlab.com/securityengineering/HyCC):
 - Addition (add)
 - Subtraction (sub)
 - Multiplication (mul)
 - Division (div)
 - Greater than (gt)
 - Greater than or equal to (geq)
 - Equal to zero (eqz)
 - Modulo reduction (mod)

The circuits for conversion with floating-point numbers are generated with [CBMC-GC2](https://gitlab.com/securityengineering/CBMC-GC-2) using modified C programs from [SoftFloat-2c](http://www.jhauser.us/arithmetic/SoftFloat.html). The modified C programs can be found [here](https://github.com/liangzhao-darmstadt/Securely-Realizing-Output-Privacy-in-MPC-using-Differential-Privacy/tree/dev/src/motioncore/utility/CBMC-GC-2-master/examples/lz_float).