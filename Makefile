CXXFLAGS = -O3 -g0 -march=native
LDFLAGS = $(CXXFLAGS)

networkseed: dns.o bitcoin.o netbase.o protocol.o db.o main.o util.o keccek.o
	g++ -pthread $(LDFLAGS) -o networkseed dns.o bitcoin.o netbase.o protocol.o db.o main.o util.o keccak.o -lcrypto

%.o: %.cpp bitcoin.h netbase.h protocol.h db.h serialize.h uint256.h util.h
	g++ -DUSE_IPV6 -pthread $(CXXFLAGS) -Wno-invalid-offsetof -c -o $@ $<

dns.o: dns.c
	gcc -pthread -std=c99 $(CXXFLAGS) dns.c -c -o dns.o

%.o: %.c sph_keccak.h sph_types.h
	g++ -pthread $(CXXFLAGS) -fpermissive -c -o $@ $<

