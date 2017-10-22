.PHONY: all clean install uninstall

GOBUILD=go build
GOGET=go get -d -v .
PREFIX=/usr/local

all: portknob

clean:
	rm -f portknob

install: portknob
	install -Dm0755 portknob "$(DESTDIR)$(PREFIX)/bin/portknob"
	install -Dm0644 portknob.conf "$(DESTDIR)/etc/portknob.conf"
	$(MAKE) -C systemd install "DESTDIR=$(DESTDIR)" "PREFIX=$(PREFIX)"

uninstall:
	rm -f "$(DESTDIR)$(PREFIX)/bin/portknob"
	$(MAKE) -C systemd uninstall "DESTDIR=$(DESTDIR)" "PREFIX=$(PREFIX)"

portknob: cache.go config.go firewall.go main.go server.go
	$(GOGET) && $(GOBUILD)
