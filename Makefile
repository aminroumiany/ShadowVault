CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic
LDFLAGS  = -lsodium -lz

TARGET  = shadowvault
SRC     = shadowvault.c

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test: $(TARGET)
	./tests/run.sh

clean:
	rm -f $(TARGET)
