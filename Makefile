CPP      = g++
CPPFLAGS = -Wall -I.
LDFLAGS  =
OUT      =

ifdef DEBUG
  CPPFLAGS += -g -fprofile-arcs -ftest-coverage
else
  CPPFLAGS += -O2 -pipe -Wuninitialized
endif

.PHONY: all clean clean_objs

# Build rules
all: objs base $(OUT)

objs:
	mkdir -p objs

base: objs/atomicops-x86.o

objs/atomicops-x86.o: base/atomicops-internals-x86.cc
	$(CPP) $(CPPFLAGS) -c $(LDFLAGS) -o objs/atomicops-x86.o base/atomicops-internals-x86.cc

# Implicit rules
.SUFFIXES: .cc

clean: clean_objs
	-rm -f $(OUT)

clean_objs:
	-rm -f objs/*.o *~ .depend

.cc.o:
	$(CPP) -c $(CPPFLAGS) -o objs/$@ $<

# TODO(vincent): uncomment the following lines when source files will be available.
# .depend: $(SRC_FILES)
# 	$(CPP) -MM $^ > $@
#
# include .depend