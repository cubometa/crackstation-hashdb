all: sortidx createidx

sortidx: sortidx.c
	gcc -Wall -O2 sortidx.c -o sortidx

createidx: createidx.c
	gcc -o createidx createidx.c
