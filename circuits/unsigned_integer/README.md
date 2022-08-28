### Circuit Description
The following circuits are generated with [HyCC](https://gitlab.com/securityengineering/HyCC):
 - Addition (add)
 - Subtraction (sub)
 - Multiplication (mul)
 - Division (div)
 - Greater than (gt)
 - Greater than or equal to (ge)
 - Equal to zero (eqz)
 - Modular reduction (mod)

The circuits for conversion with floating-point numbers are generated with [CBMC-GC2](https://gitlab.com/securityengineering/CBMC-GC-2) using modified C programs from [SoftFloat-2c](http://www.jhauser.us/arithmetic/SoftFloat.html). The modified C programs can be found at folder `C_program/CBMC-GC-2/int_to_float`