CPP      = g++
CPPFLAGS = -funsigned-char -fno-exceptions -Wall -Werror -Wformat -I.
LDFLAGS  = -lpthread -lgflags -lnfnetlink -lnetfilter_conntrack -lnetfilter_queue -lboost_regex
OUT      = urlfilter

ifdef DEBUG
  CPPFLAGS += -g
  LDFLAGS  += -lprofiler -ltcmalloc
else
  CPPFLAGS += -O2 -pipe -Wuninitialized -DNDEBUG
endif

# Base rules.
all: base $(OUT)

clean:
	-rm -f $(OUT)
	-rm -f objs/*.o *~ .depend

base: objs/atomicops.o objs/logging.o objs/util.o

objs/atomicops.o: base/atomicops-internals-x86.cc base/atomicops-internals-x86.h base/atomicops.h
	$(CPP) $(CPPFLAGS) -c -o $@ base/atomicops-internals-x86.cc

objs/io.o: base/io.cc base/io.h
	$(CPP) $(CPPFLAGS) -c -o $@ base/io.cc

objs/logging.o: base/logging.cc base/logging.h
	$(CPP) $(CPPFLAGS) -c -o $@ base/logging.cc

objs/util.o: base/util.cc base/util.h
	$(CPP) $(CPPFLAGS) -c -o $@ base/util.cc

# Project build rules.
objs/classifier.o: classifier.cc classifier.h
	$(CPP) $(CPPFLAGS) -c -o $@ classifier.cc

objs/conntrack.o: conntrack.cc conntrack.h
	$(CPP) $(CPPFLAGS) -c -o $@ conntrack.cc

objs/packet.o: packet.cc packet.h
	$(CPP) $(CPPFLAGS) -c -o $@ packet.cc

objs/queue.o: queue.cc queue.h
	$(CPP) $(CPPFLAGS) -c -o $@ queue.cc

urlfilter: urlfilter.cc objs/classifier.o objs/conntrack.o objs/packet.o objs/queue.o objs/atomicops.o objs/io.o objs/logging.o objs/util.o
	$(CPP) $(CPPFLAGS) $(LDFLAGS) -o $@ $+

# Report.
report: report/rapport.pdf

report/rapport.pdf: report/but.tex report/concl.tex report/implementation.tex report/intro.tex report/rapport.tex report/biblio.bib
	pdflatex -interaction=batchmode -output-directory=report rapport.tex > /dev/null
