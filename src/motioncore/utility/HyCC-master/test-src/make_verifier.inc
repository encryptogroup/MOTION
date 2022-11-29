.PHONY: run clean

verifier.c: mpc_main.circ
	$(CIRCUIT_UTILS) mpc_main.circ --create-verifier verifier.c --reference reference.c $(CIRCUIT_UTILS_FLAGS)

mpc_main.circ: reference.c $(CBMC_GC) $(CBMC_GC_FLAGS_FILE)
	$(CBMC_GC) --compile-options > CBMC_GC_INFO
	$(CBMC_GC) reference.c $(CBMC_GC_FLAGS)

run: verifier.c
	$(CBMC) verifier.c --trace

clean:
	rm -f verifier.c
	rm -f mpc_main.circ
	rm -f mpc_main.stats

