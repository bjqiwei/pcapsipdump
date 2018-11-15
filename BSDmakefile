LIBS ?= -lpcap -lstdc++
RELEASEFLAGS ?= -O3 -Wall
BSDSTR_DEFS := -DBSD
BSDSTR_LIBS :=

all: pcapsipdump

pcapsipdump: *.cpp *.h
	$(CXX) $(RELEASEFLAGS) $(CXXFLAGS) $(LDFLAGS) $(DEFS) $(BSDSTR_DEFS) \
	*.cpp \
	$(LIBS) $(BSDSTR_LIBS) \
	-o pcapsipdump

clean:
	rm -f pcapsipdump
