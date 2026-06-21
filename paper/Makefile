# Build the SQLite recovery paper (XeLaTeX + BibTeX).
PAPER = sqlite-recovery

.PHONY: all clean
all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex $(PAPER).bib
	xelatex -interaction=nonstopmode -halt-on-error $(PAPER).tex
	bibtex $(PAPER)
	xelatex -interaction=nonstopmode -halt-on-error $(PAPER).tex
	xelatex -interaction=nonstopmode -halt-on-error $(PAPER).tex

clean:
	rm -f $(PAPER).aux $(PAPER).bbl $(PAPER).blg $(PAPER).log $(PAPER).out
