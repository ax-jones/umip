
SUBDIRS = src

.PHONY: clean $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	@for dir in $(SUBDIRS); do (cd $$dir; $(MAKE) clean); done
	rm umip.elf umip.elf.stripped

all: $(SUBDIRS)

