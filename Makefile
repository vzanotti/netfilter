CPP      = g++
CPPFLAGS = -funsigned-char -Wall -Werror -Wformat -I.
LDFLAGS  =
OUT      =

ifdef DEBUG
  CPPFLAGS += -g
else
  CPPFLAGS += -O2 -pipe -Wuninitialized
endif

# Base rules.
all: base $(OUT)

clean:
	-rm -f $(OUT)
	-rm -f objs/*.o *~ .depend

base: objs/atomics.o objs/logging.o objs/util.o

objs/atomics.o: base/atomicops-internals-x86.cc base/atomicops-internals-x86.h base/atomicops.h
	$(CPP) $(CPPFLAGS) -c -o $@ base/atomicops-internals-x86.cc

objs/logging.o: base/logging.cc base/logging.h
	$(CPP) $(CPPFLAGS) -c -o $@ base/logging.cc

objs/util.o: base/util.cc base/util.h
	$(CPP) $(CPPFLAGS) -c -o $@ base/util.cc

# Project build rules.
