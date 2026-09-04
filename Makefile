CC      = /home/kali/gcc-outlaws/bin/outlaws-gcc
CFLAGS  = -O2 -Wall -Wextra -Wpedantic
LDFLAGS = -lsodium -lz

TARGET  = shadowvault
SRC     = shadowvault.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET)
