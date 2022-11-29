GCC_FLAGS ?= -O2

.PHONY: run clean

tester: tester.cpp
	g++ $(GCC_FLAGS) tester.cpp -o tester

tester.cpp: output.gate.txt
	$(CIRCUIT_UTILS) --create-tester tester.cpp --reference reference.c $(CIRCUIT_UTILS_FLAGS)

output.gate.txt: reference.c $(CBMC_GC) $(CBMC_GC_FLAGS_FILE)
	$(CBMC_GC) reference.c $(CBMC_GC_FLAGS)

run: tester
	./tester

clean:
	rm -f tester.cpp
	rm -f tester
	rm -f output.*.txt
