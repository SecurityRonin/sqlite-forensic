# Build the SQLite recovery paper (pdfLaTeX + BibTeX).
PAPER = sqlite-recovery

.PHONY: all clean
all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex $(PAPER).bib
	pdflatex -interaction=nonstopmode -halt-on-error $(PAPER).tex
	bibtex $(PAPER)
	pdflatex -interaction=nonstopmode -halt-on-error $(PAPER).tex
	pdflatex -interaction=nonstopmode -halt-on-error $(PAPER).tex

clean:
	rm -f $(PAPER).aux $(PAPER).bbl $(PAPER).blg $(PAPER).log $(PAPER).out
