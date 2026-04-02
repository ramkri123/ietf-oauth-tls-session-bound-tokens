# Makefile for IETF Draft

DRAFT := draft-mw-oauth-tls-session-bound-tokens-03
MMARK := $(HOME)/go/bin/mmark
XML2RFC := $(HOME)/local/bin/xml2rfc

# If xml2rfc is in path, use it, otherwise use the local one
ifeq (, $(shell which xml2rfc))
	XML2RFC := $(HOME)/.local/bin/xml2rfc
else
	XML2RFC := xml2rfc
endif

.PHONY: all clean txt html xml

all: txt html

txt: $(DRAFT).txt
html: $(DRAFT).html
xml: $(DRAFT).xml

$(DRAFT).xml: draft-mw-oauth-tls-session-bound-tokens.md
	$(MMARK) $< > $@

$(DRAFT).txt: $(DRAFT).xml
	$(XML2RFC) --text $< -o $@

$(DRAFT).html: $(DRAFT).xml
	$(XML2RFC) --html $< -o $@

clean:
	rm -f $(DRAFT).xml $(DRAFT).txt $(DRAFT).html
