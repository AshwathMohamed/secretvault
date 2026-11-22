# builds the syscall benchmark ($@ = the target name, $< = the first dependency)
syscall_bench: syscall_bench.c
	$(CC) -O2 -o $@ $<
clean:
	rm -f syscall_bench
