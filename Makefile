all: sortidx createidx

.PHONY: all clean test testclean

all: sortidx checksort createidx

sortidx: sortidx.c
	gcc -Wall -O3 sortidx.c -o sortidx

createidx: createidx.c
	gcc -o createidx createidx.c

checksort: checksort.c
	gcc -Wall -O3 checksort.c -o checksort

clean:
	rm -f sortidx checksort

test:
	./test/test.sh

testclean:
	rm -f test-index-files/test-words*.idx
	rm -fd test-index-files
