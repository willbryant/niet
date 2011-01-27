all: niet test/output_on_both

niet: src/niet.o
	cc -o $@ $^

test/output_on_both: test/output_on_both.o
	cc -o $@ $^

clean:
	rm -f src/niet.o niet test/output_on_both.o test/output_on_both
