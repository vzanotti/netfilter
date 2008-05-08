CPP      = g++
CPPFLAGS = -Wall -Werror -Wformat -I.
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

base: objs/util.o

objs/util.o: base/util.cc
	$(CPP) $(CPPFLAGS) -c -o $@ base/util.cc

# Project build rules.

# TODO(vincent): uncomment the following lines when source files will be available.
# .depend: $(SRC_FILES)
# 	$(CPP) -MM $^ > $@
#
# include .depend