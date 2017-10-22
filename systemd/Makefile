.PHONY: install uninstall

PREFIX = /usr/local
SYSTEMD_DIR = /usr/lib/systemd
SYSTEMD_UNIT_DIR = $(SYSTEMD_DIR)/system

install:
	install -Dm0644 portknob.service "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/portknob.service"
	systemctl daemon-reload || true

uninstall:
	rm -f "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/portknob.service"
	systemctl daemon-reload || true
