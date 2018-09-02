
all: man1/nmap-analyze.1

man1/nmap-analyze.1: nmap-analyze.1.md man1 pandoc
	@pandoc -s -t man $< -o $@
	@sed -i.bk 's/\.TH.*/.TH "nmap-analyze" "1"/g' man1/nmap-analyze.1
	@rm -f man1/nmap-analyze.1.bk

man1:
	@mkdir $@

pandoc:
	@pandoc --version > /dev/null

view: man1/nmap-analyze.1
	@man -M . 1 nmap-analyze

clean:
	@-rm -R man1

.PHONY: pandoc view clean

