
include_HEADERS = include/aiwendb.h

nodist_include_HEADERS = include/aiwendb_config.h

SUBDIRS = \
  src

dist-hook:
	
	find $(distdir) -name '.git*' | xargs rm -fr

safedist: clean dist
	tmpdir="$${TMPDIR-/tmp}/safedist-$$$$" \
	  && mkdir "$$tmpdir" \
	  && tar -xvf $(distdir).tar.gz --directory "$$tmpdir" \
	  && $(am__cd) "$$tmpdir/$(distdir)" \
	  && ./configure \
	  && make -j 4 check



