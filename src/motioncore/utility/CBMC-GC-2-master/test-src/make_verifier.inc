.PHONY: run clean

verifier.c: output.gate.txt
	$(CIRCUIT_UTILS) --create-verifier verifier.c --reference reference.c $(CIRCUIT_UTILS_FLAGS)

output.gate.txt: reference.c $(CBMC_GC) $(CBMC_GC_FLAGS_FILE)
	$(CBMC_GC) reference.c $(CBMC_GC_FLAGS)

run: verifier.c
	cbmc verifier.c --trace

clean:
	rm -f verifier.c
	rm -f output.*.txt

