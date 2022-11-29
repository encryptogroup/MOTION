liangzhao@aw17r4:~/Documents/CBMC-GC-2-master$ cd examples/
liangzhao@aw17r4:~/Documents/CBMC-GC-2-master/examples$ cd lz_fixpoint64\ \(shift\ not\ working\)/
liangzhao@aw17r4:~/Documents/CBMC-GC-2-master/examples/lz_fixpoint64 (shift not working)$ make
make clean_all
make[1]: Entering directory '/home/liangzhao/Documents/CBMC-GC-2-master/examples/lz_fixpoint64 (shift not working)'
rm -f *.circ *.stats *.txt *.bristol
make[1]: Leaving directory '/home/liangzhao/Documents/CBMC-GC-2-master/examples/lz_fixpoint64 (shift not working)'
echo mul; ../../bin/cbmc-gc fix64_mul.c --low-depth --outline --minimization-time-limit 360000 --unwind 1000000; mv mpc_main.circ fix64_mul_depth.circ;  fix64_mul_depth.circ --as-bristol fix64_mul_depth.bristol; 
mul
Usage error!


* *   CBMC 5.7 - Copyright (C) 2001-2016 (64-bit version)   * *
* *              Daniel Kroening, Edmund Clarke             * *
* * Carnegie Mellon University, Computer Science Department * *
* *                 kroening@kroening.com                   * *
* *        Protected in part by U.S. patent 7,225,417       * *

Usage:                       Purpose:

 cbmc [-?] [-h] [--help]      show help
 cbmc file.c ...              source file names

Garbled circuit options:
 --no-minimization            do no try to minimize the circuit
 --minimization-time-limit t  limit minimization time to t seconds
 --low-depth                  same as specifying both --low-depth-bb and
                              --low-depth-expr
 --low-depth-bb               use building blocks optimized for circuit depth
 --low-depth-expr             optimize expressions for circuit depth
 --outdir dir                 write the circuit files to directory dir

Analysis options:
 --show-properties            show the properties, but don't run analysis
 --property id                only check one specific property
 --stop-on-fail               stop analysis once a failed property is detected
 --trace                      give a counterexample trace for failed properties

C/C++ frontend options:
 -I path                      set include path (C/C++)
 -D macro                     define preprocessor macro (C/C++)
 --preprocess                 stop after preprocessing
 --16, --32, --64             set width of int
 --LP64, --ILP64, --LLP64,
   --ILP32, --LP32            set width of int, long and pointers
 --little-endian              allow little-endian word-byte conversions
 --big-endian                 allow big-endian word-byte conversions
 --unsigned-char              make "char" unsigned by default
 --mm model                   set memory model (default: sc)
 --arch                       set architecture (default: x86_64)
 --os                         set operating system (default: linux)
 --c89/99/11                  set C language standard (default: c99)
 --cpp98/03/11                set C++ language standard (default: cpp98)
 --no-arch                    don't set up an architecture
 --no-library                 disable built-in abstract C library
 --round-to-nearest           rounding towards nearest even (default)
 --round-to-plus-inf          rounding towards plus infinity
 --round-to-minus-inf         rounding towards minus infinity
 --round-to-zero              rounding towards zero
 --function name              set main function name

Program representations:
 --show-parse-tree            show parse tree
 --show-symbol-table          show symbol table
 --show-goto-functions        show goto program

Program instrumentation options:
 --bounds-check               enable array bounds checks
 --pointer-check              enable pointer checks
 --memory-leak-check          enable memory leak checks
 --div-by-zero-check          enable division by zero checks
 --signed-overflow-check      enable signed arithmetic over- and underflow checks
 --unsigned-overflow-check    enable arithmetic over- and underflow checks
 --pointer-overflow-check     enable pointer arithmetic over- and underflow checks
 --conversion-check           check whether values can be represented after type cast
 --undefined-shift-check      check shift greater than bit-width
 --float-overflow-check       check floating-point for +/-Inf
 --nan-check                  check floating-point for NaN
 --no-assertions              ignore user assertions
 --no-assumptions             ignore user assumptions
 --error-label label          check that label is unreachable
 --cover CC                   create test-suite with coverage criterion CC
 --mm MM                      memory consistency model for concurrent programs

Java Bytecode frontend options:
 --classpath dir/jar          set the classpath
 --main-class class-name      set the name of the main class

Semantic transformations:
 --nondet-static              add nondeterministic initialization of variables with static lifetime

BMC options:
 --program-only               only show program expression
 --show-loops                 show the loops in the program
 --depth nr                   limit search depth
 --unwind nr                  unwind nr times
 --unwindset L:B,...          unwind loop L with a bound of B
                              (use --show-loops to get the loop IDs)
 --show-vcc                   show the verification conditions
 --slice-formula              remove assignments unrelated to property
 --unwinding-assertions       generate unwinding assertions
 --partial-loops              permit paths with partial loops
 --no-pretty-names            do not simplify identifiers
 --graphml-witness filename   write the witness in GraphML format to filename

Backend options:
 --dimacs                     generate CNF in DIMACS format
 --beautify                   beautify the counterexample (greedy heuristic)
 --localize-faults            localize faults (experimental)
 --smt1                       use default SMT1 solver (obsolete)
 --smt2                       use default SMT2 solver (Z3)
 --boolector                  use Boolector
 --mathsat                    use MathSAT
 --cvc4                       use CVC4
 --yices                      use Yices
 --z3                         use Z3
 --refine                     use refinement procedure (experimental)
 --outfile filename           output formula to given file
 --arrays-uf-never            never turn arrays into uninterpreted functions
 --arrays-uf-always           always turn arrays into uninterpreted functions

Other options:
 --version                    show version and exit
 --xml-ui                     use XML-formatted output
 --xml-interface              bi-directional XML interface
 --json-ui                    use JSON-formatted output

mv: cannot stat 'mpc_main.circ': No such file or directory
/bin/sh: 1: fix64_mul_depth.circ: not found
make: *** [Makefile:14: all] Error 127
liangzhao@aw17r4:~/Documents/CBMC-GC-2-master/examples/lz_fixpoint64 (shift not working)$ makemake
makemake: command not found
liangzhao@aw17r4:~/Documents/CBMC-GC-2-master/examples/lz_fixpoint64 (shift not working)$ make
make clean_all
make[1]: Entering directory '/home/liangzhao/Documents/CBMC-GC-2-master/examples/lz_fixpoint64 (shift working)'
rm -f *.circ *.stats *.txt *.bristol
make[1]: Leaving directory '/home/liangzhao/Documents/CBMC-GC-2-master/examples/lz_fixpoint64 (shift working)'
echo mul; ../../bin/cbmc-gc fix64_mul.c --low-depth --outline --minimization-time-limit 360000 --unwind 1000000; mv mpc_main.circ fix64_mul_depth.circ;  fix64_mul_depth.circ --as-bristol fix64_mul_depth.bristol; 
mul
Usage error!


* *   CBMC 5.7 - Copyright (C) 2001-2016 (64-bit version)   * *
* *              Daniel Kroening, Edmund Clarke             * *
* * Carnegie Mellon University, Computer Science Department * *
* *                 kroening@kroening.com                   * *
* *        Protected in part by U.S. patent 7,225,417       * *

Usage:                       Purpose:

 cbmc [-?] [-h] [--help]      show help
 cbmc file.c ...              source file names

Garbled circuit options:
 --no-minimization            do no try to minimize the circuit
 --minimization-time-limit t  limit minimization time to t seconds
 --low-depth                  same as specifying both --low-depth-bb and
                              --low-depth-expr
 --low-depth-bb               use building blocks optimized for circuit depth
 --low-depth-expr             optimize expressions for circuit depth
 --outdir dir                 write the circuit files to directory dir

Analysis options:
 --show-properties            show the properties, but don't run analysis
 --property id                only check one specific property
 --stop-on-fail               stop analysis once a failed property is detected
 --trace                      give a counterexample trace for failed properties

C/C++ frontend options:
 -I path                      set include path (C/C++)
 -D macro                     define preprocessor macro (C/C++)
 --preprocess                 stop after preprocessing
 --16, --32, --64             set width of int
 --LP64, --ILP64, --LLP64,
   --ILP32, --LP32            set width of int, long and pointers
 --little-endian              allow little-endian word-byte conversions
 --big-endian                 allow big-endian word-byte conversions
 --unsigned-char              make "char" unsigned by default
 --mm model                   set memory model (default: sc)
 --arch                       set architecture (default: x86_64)
 --os                         set operating system (default: linux)
 --c89/99/11                  set C language standard (default: c99)
 --cpp98/03/11                set C++ language standard (default: cpp98)
 --no-arch                    don't set up an architecture
 --no-library                 disable built-in abstract C library
 --round-to-nearest           rounding towards nearest even (default)
 --round-to-plus-inf          rounding towards plus infinity
 --round-to-minus-inf         rounding towards minus infinity
 --round-to-zero              rounding towards zero
 --function name              set main function name

Program representations:
 --show-parse-tree            show parse tree
 --show-symbol-table          show symbol table
 --show-goto-functions        show goto program

Program instrumentation options:
 --bounds-check               enable array bounds checks
 --pointer-check              enable pointer checks
 --memory-leak-check          enable memory leak checks
 --div-by-zero-check          enable division by zero checks
 --signed-overflow-check      enable signed arithmetic over- and underflow checks
 --unsigned-overflow-check    enable arithmetic over- and underflow checks
 --pointer-overflow-check     enable pointer arithmetic over- and underflow checks
 --conversion-check           check whether values can be represented after type cast
 --undefined-shift-check      check shift greater than bit-width
 --float-overflow-check       check floating-point for +/-Inf
 --nan-check                  check floating-point for NaN
 --no-assertions              ignore user assertions
 --no-assumptions             ignore user assumptions
 --error-label label          check that label is unreachable
 --cover CC                   create test-suite with coverage criterion CC
 --mm MM                      memory consistency model for concurrent programs

Java Bytecode frontend options:
 --classpath dir/jar          set the classpath
 --main-class class-name      set the name of the main class

Semantic transformations:
 --nondet-static              add nondeterministic initialization of variables with static lifetime

BMC options:
 --program-only               only show program expression
 --show-loops                 show the loops in the program
 --depth nr                   limit search depth
 --unwind nr                  unwind nr times
 --unwindset L:B,...          unwind loop L with a bound of B
                              (use --show-loops to get the loop IDs)
 --show-vcc                   show the verification conditions
 --slice-formula              remove assignments unrelated to property
 --unwinding-assertions       generate unwinding assertions
 --partial-loops              permit paths with partial loops
 --no-pretty-names            do not simplify identifiers
 --graphml-witness filename   write the witness in GraphML format to filename

Backend options:
 --dimacs                     generate CNF in DIMACS format
 --beautify                   beautify the counterexample (greedy heuristic)
 --localize-faults            localize faults (experimental)
 --smt1                       use default SMT1 solver (obsolete)
 --smt2                       use default SMT2 solver (Z3)
 --boolector                  use Boolector
 --mathsat                    use MathSAT
 --cvc4                       use CVC4
 --yices                      use Yices
 --z3                         use Z3
 --refine                     use refinement procedure (experimental)
 --outfile filename           output formula to given file
 --arrays-uf-never            never turn arrays into uninterpreted functions
 --arrays-uf-always           always turn arrays into uninterpreted functions

Other options:
 --version                    show version and exit
 --xml-ui                     use XML-formatted output
 --xml-interface              bi-directional XML interface
 --json-ui                    use JSON-formatted output

mv: cannot stat 'mpc_main.circ': No such file or directory
/bin/sh: 1: fix64_mul_depth.circ: not found
make: *** [Makefile:14: all] Error 127
liangzhao@aw17r4:~/Documents/CBMC-GC-2-master/examples/lz_fixpoint64 (shift not working)$ 
