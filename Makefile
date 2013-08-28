
SUBDIRS = src

.PHONY: clean $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	@for dir in $(SUBDIRS); do (cd $$dir; $(MAKE) clean); done

all: $(SUBDIRS)

