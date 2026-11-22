# top-level Makefile: "make" builds the module and the benchmark, "make test" also runs the tests
all:
	$(MAKE) -C module
	$(MAKE) -C bench
clean:
	$(MAKE) -C module clean
	$(MAKE) -C bench clean
test: all
	sudo tests/run_all.sh
