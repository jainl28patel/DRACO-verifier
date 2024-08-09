SUBDIRS := $(wildcard */.)

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) verify-interactions

.PHONY: $(TOPTARGETS) $(SUBDIRS)
