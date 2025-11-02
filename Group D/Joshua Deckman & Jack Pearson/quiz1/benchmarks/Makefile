BIN = bin
OBJ = obj
REPORTS = reports

CFLAGS = -g -march=armv8.2-a+crypto

SPECDIR = bench-specs
SPECS = $(wildcard $(SPECDIR)/*.cfg)
NAMES = $(filter-out zero,$(notdir $(basename $(SPECS))))
REPORT_TARGETS = $(NAMES:%=$(REPORTS)/report-%.txt)

REPT_COUNT = 1000000

$(OBJ)/run-asm-zero.o: run-asm.c | $(OBJ)/
	${COMPILE.c} -DREPT_COUNT=0 @bench-specs/zero.cfg -o $@ $^

$(OBJ)/run-asm-%.o: run-asm.c | $(OBJ)/
	${COMPILE.c} -DREPT_COUNT=$(REPT_COUNT) @bench-specs/$*.cfg -o $@ $^

$(BIN)/run-asm-%: $(OBJ)/run-asm-%.o | $(BIN)/
	${LINK.o} -o $@ $^


$(REPORTS)/report-%.txt: bench-asm.sh $(BIN)/run-asm-zero $(BIN)/run-asm-% | $(REPORTS)/
	./$^ $* $(REPT_COUNT) >$@

%/::
	mkdir -p $@

main-report.txt: $(REPORT_TARGETS)
	echo "Main Report using $(REPT_COUNT) instructions for each benchmark" >>$@
	echo >>$@
	echo "| benchmark | cycles/instr | total execution time |" >>$@
	echo "| --------- | ------------ | -------------------- |" >>$@
	cat $^ >>$@


.DEFAULT_GOAL := main-report.txt

.PRECIOUS: %/

clean:
	rm -rf main-report.txt $(REPORTS) $(BIN) $(OBJ)
