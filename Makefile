CC = gcc
CFLAGS = -Wall -Werror -pedantic -std=gnu99
SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
LINKER_LIBS = -levent
COMPILE_LIBS = 
DEBUG = -g

.PHONY: clean

all: $(OBJECTS)
	$(CC) $(LINKER_LIBS) $(OBJECTS) -o greu

.c.o:
	$(CC) $(CFLAGS) $(COMPILE_LIBS) -c $< -o $@

clean:
	rm -rf *.o greu
