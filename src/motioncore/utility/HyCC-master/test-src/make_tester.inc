GCC_FLAGS ?= -O2

.PHONY: run clean

tester: tester.cpp
	g++ $(GCC_FLAGS) tester.cpp -o tester

tester.cpp: mpc_main.circ
	$(CIRCUIT_UTILS) mpc_main.circ --create-tester tester.cpp --reference reference.c $(CIRCUIT_UTILS_FLAGS)

mpc_main.circ: reference.c $(CBMC_GC) $(CBMC_GC_FLAGS_FILE)
	$(CBMC_GC) --compile-options > CBMC_GC_INFO
	$(CBMC_GC) reference.c $(CBMC_GC_FLAGS)

run: tester
	./tester

clean:
	rm -f tester.cpp
	rm -f tester
	rm -f mpc_main.circ
	rm -f mpc_main.stats
