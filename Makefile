all: $(EXEC)

CFLAGS = -Wall -std=c++11 -O3 
HEADER += hash.h util.h datatypes.hpp adaptor.hpp drex.hpp 
SRC += hash.c adaptor.cpp drex.cpp 

LIBS= -lpcap -lm

main: main.cpp $(SRC) $(HEADER) 
	g++ $(CFLAGS) $(INCLUDES) -o $@ $< $(SRC) $(LIBS)

clean:
	rm -rf $(EXEC)
	rm -rf *log*
	rm -rf *out*