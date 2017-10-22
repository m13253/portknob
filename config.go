/*
    portknob -- Port knocking daemon with web interface
    Copyright (C) 2017 Star Brilliant <m13253@hotmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"log"
	"net"
	"os"
	"strings"
	"github.com/BurntSushi/toml"
)

type config struct {
	Daemon		configDaemon		`toml:"daemon"`
	Firewall	[]configFirewall	`toml:"firewall"`
	Secrets		map[string]string	`toml:"secrets"`
}

type configDaemon struct {
	// HTTP address and port to listen on
	// Default: "[::1]:706"
	Listen				string	`toml:"listen"`

	// HTTP path to provide service on
	// Default: "/"
	HTTPPath			string	`toml:"http-path"`

	// HTTP header provided by the SLB indicating the visitor's IP address
	// Default: "X-Real-IP"
	ClientIP			string	`toml:"client-ip"`

	// IPv4 subnet prefix to add to the firewall whitelist
	// Default: 24
	IPv4Prefix			uint	`toml:"ipv4-prefix"`

	// IPv6 subnet prefix to add to the firewall whitelist
	// Default: 48
	IPv6Prefix			uint	`toml:"ipv6-prefix"`

	// File name in which stores the cache database
	// Default: "portknob.db"
	CacheDatabase		string	`toml:"cache-database"`

	// Lifespan to cache authorization info in visitor's web browser
	// Default: 604800 (7 days)
	CookieLifespan		uint	`toml:"cookie-lifespan"`

	// Lifespan to cache firewall whitelist for the visitor
	// Default: 604800 (7 days)
	FirewallLifespan	uint	`toml:"firewall-lifespan"`

	// Firewall chain name for Portknob to work on
	// Default: "portknob"
	FirewallChainName	string	`toml:"firewall-chain-name"`

	// Firewall rule to deny unauthorized clients
	// Possible values:
	// - "drop": silently drop any incoming requests, this works better if your firewall also drops incoming requests to other unoccupied ports
	// - "reject": rejects incoming requests with "connection refused" reply, this works better if your firewall does not drop incoming requests to other unoccupied ports
	// Default: "reject"
	FirewallDenyMethod	string	`toml:"firewall-deny-method"`
}

type configFirewall struct {
	// Firewall rule comment
	// Default: ""
	Comment		string		`toml:"comment"`

	// Protocol name
	// Supported values: "tcp", "udp", "" (both)
	// Default: "" (both)
	Proto		string		`toml:"proto"`

	// Destination IP
	// Supported values: IPv4, IPv6, "any" (0.0.0.0/0 and ::/0)
	// Default: "any" (0.0.0.0/0 and ::/0)
	Dest		string		`toml:"dest"`
	DestIP		net.IP		`toml:"-"`

	// Destination Port
	// This is a mandatory option
	// Use "port" to specify a port number
	// Use "first:last" to specify an inclusive range
	DestPort	string		`toml:"dport"`
}

func loadConfig(path string) (*config, error) {
	conf := &config {}
	metaData, err := toml.DecodeFile(path, conf)
	if err != nil {
		return nil, err
	}

	undecoded := metaData.Undecoded()
	for _, key := range metaData.Undecoded() {
		log.Printf("unknown option %q\n", key.String())
	}
	if len(undecoded) != 0 {
		os.Exit(1)
	}

	if conf.Daemon.Listen == "" {
		conf.Daemon.Listen = "[::1]:706"
	}
	if conf.Daemon.HTTPPath == "" {
		conf.Daemon.HTTPPath = "/"
	}
	if conf.Daemon.ClientIP == "" {
		conf.Daemon.ClientIP = "X-Real-IP"
	}
	if conf.Daemon.IPv4Prefix == 0 {
		conf.Daemon.IPv4Prefix = 24
	}
	if conf.Daemon.IPv6Prefix == 0 {
		conf.Daemon.IPv6Prefix = 48
	}
	if conf.Daemon.CacheDatabase == "" {
		conf.Daemon.CacheDatabase = "portknob.db"
	}
	if conf.Daemon.CookieLifespan == 0 {
		conf.Daemon.CookieLifespan = 604800
	}
	if conf.Daemon.FirewallLifespan == 0 {
		conf.Daemon.FirewallLifespan = 604800
	}
	if conf.Daemon.FirewallChainName == "" {
		conf.Daemon.FirewallChainName = "portknob"
	}
	if conf.Daemon.FirewallDenyMethod == "" {
		conf.Daemon.FirewallDenyMethod = "reject"
	} else if conf.Daemon.FirewallDenyMethod != "drop" && conf.Daemon.FirewallDenyMethod != "reject" {
		conf.reportConfigError("filewall-deny-method", conf.Daemon.FirewallDenyMethod)
	}

	for i, v := range conf.Firewall {
		if v.Proto != "tcp" && v.Proto != "udp" && v.Proto != "" {
			conf.reportConfigError("proto", v.Proto)
		}
		if v.Dest == "any" || v.Dest == "" {
			conf.Firewall[i].Dest = ""
			conf.Firewall[i].DestIP = nil
		} else {
			slash := strings.IndexByte(v.Dest, '/')
			if slash < 0 {
				slash = len(v.Dest)
			}
			conf.Firewall[i].DestIP = net.ParseIP(v.Dest[:slash])
			if conf.Firewall[i].DestIP == nil {
				conf.reportConfigError("dest", v.Dest)
			}
		}
		if v.DestPort == "" {
			log.Fatalf("option \"dport\" not specified\n")
		}
	}

	return conf, nil
}

func (conf *config) reportConfigError(option, value string) {
	log.Fatalf("option %q does not support %q\n", option, value)
}
