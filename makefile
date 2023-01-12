CC = g++
LDLIBS = -lpcap

all: beacon-flood

beacon-flood: main.o mac.o beacon-flood.o
	$(CC) $^ -o $@ $(LDLIBS)

clean:
	@rm -f ./airodump *.o