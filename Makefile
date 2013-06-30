default: niet
all: niet test/output_on_both test/ignore_term

install: niet
	install $^ /usr/local/bin

install_to_usr_bin: niet
	install $^ /usr/bin

niet: src/niet.o
	cc -o $@ $^

test/output_on_both: test/output_on_both.o
	cc -o $@ $^

test/ignore_term: test/ignore_term.o
	cc -o $@ $^

clean:
	rm -f src/niet.o niet test/output_on_both.o test/output_on_both test/ignore_term.o test/ignore_term
