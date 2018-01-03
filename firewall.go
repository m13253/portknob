/*
    portknob -- Port knocking daemon with web interface
    Copyright (C) 2017 Star Brilliant <m13253@hotmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type firewall struct {
	conf		*config
	cache		*cache
	chainName	string
	denyName	string
	net4Name	string
	net6Name	string
	host4Name	string
	host6Name	string
	stopReq		chan os.Signal
}

func newFirewall(conf *config) *firewall {
	fw := &firewall {
		conf:		conf,
		cache:		newCache(conf),
		chainName:	conf.Daemon.FirewallChainName,
		denyName:	conf.Daemon.FirewallChainName + "-deny",
		net4Name:	conf.Daemon.FirewallChainName + "-net4",
		net6Name:	conf.Daemon.FirewallChainName + "-net6",
		host4Name:	conf.Daemon.FirewallChainName + "-host4",
		host6Name:	conf.Daemon.FirewallChainName + "-host6",
		stopReq:	make(chan os.Signal, 1),
	}
	return fw
}

func (fw *firewall) Start() error {
	err := fw.cache.Start()
	if err != nil { return err }

	signal.Notify(fw.stopReq, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	// ipset
	if *fw.conf.Daemon.FirewallLifespan != 0 {
		err = fw.execCmd("ipset", "-exist", "create", fw.net4Name, "hash:ip", "family", "inet", "netmask", strconv.FormatUint(uint64(fw.conf.Daemon.IPv4Prefix), 10), "timeout", strconv.FormatUint(*fw.conf.Daemon.FirewallLifespan, 10))
		if err != nil { return err }
		err = fw.execCmd("ipset", "-exist", "create", fw.net6Name, "hash:ip", "family", "inet6", "netmask", strconv.FormatUint(uint64(fw.conf.Daemon.IPv6Prefix), 10), "timeout", strconv.FormatUint(*fw.conf.Daemon.FirewallLifespan, 10))
		if err != nil { return err }
		err = fw.execCmd("ipset", "-exist", "create", fw.host4Name, "hash:ip", "family", "inet", "timeout", strconv.FormatUint(*fw.conf.Daemon.FirewallLifespan, 10))
		if err != nil { return err }
		err = fw.execCmd("ipset", "-exist", "create", fw.host6Name, "hash:ip", "family", "inet6", "timeout", strconv.FormatUint(*fw.conf.Daemon.FirewallLifespan, 10))
		if err != nil { return err }
	} else {
		err = fw.execCmd("ipset", "-exist", "create", fw.net4Name, "hash:ip", "family", "inet", "netmask", strconv.FormatUint(uint64(fw.conf.Daemon.IPv4Prefix), 10))
		if err != nil { return err }
		err = fw.execCmd("ipset", "-exist", "create", fw.net6Name, "hash:ip", "family", "inet6", "netmask", strconv.FormatUint(uint64(fw.conf.Daemon.IPv6Prefix), 10))
		if err != nil { return err }
		err = fw.execCmd("ipset", "-exist", "create", fw.host4Name, "hash:ip", "family", "inet")
		if err != nil { return err }
		err = fw.execCmd("ipset", "-exist", "create", fw.host6Name, "hash:ip", "family", "inet6")
		if err != nil { return err }
	}


	// IPv4 deny
	fw.execCmd("iptables", "-t", "filter", "-N", fw.denyName)
	if fw.conf.Daemon.FirewallDenyMethod == "reject" {
		err = fw.execCmd("iptables", "-t", "filter", "-I", fw.denyName, "-j", "REJECT", "--reject-with", "icmp-port-unreachable")
		if err != nil { return err }
		err = fw.execCmd("iptables", "-t", "filter", "-I", fw.denyName, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset")
		if err != nil { return err }
	} else {
		err = fw.execCmd("iptables", "-t", "filter", "-I", fw.denyName, "-j", "DROP")
		if err != nil { return err }
	}
	err = fw.execCmd("iptables", "-t", "filter", "-I", fw.denyName, "-m", "limit", "--limit", "3/min", "-j", "LOG", "--log-prefix", "[PORTKNOB-DENY] ")
	if err != nil { return err }
	fw.execCmd("iptables", "-t", "filter", "-N", fw.chainName)
	err = fw.execCmd("iptables", "-t", "filter", "-I", fw.chainName, "-j", "RETURN")
	if err != nil { return err }

	// IPv4 redir
	fw.execCmd("iptables", "-t", "nat", "-N", fw.chainName)
	err = fw.execCmd("iptables", "-t", "nat", "-I", fw.chainName, "-j", "RETURN")
	if err != nil { return err }

	// IPv6 deny
	fw.execCmd("ip6tables", "-t", "filter", "-N", fw.denyName)
	if fw.conf.Daemon.FirewallDenyMethod == "reject" {
		err = fw.execCmd("ip6tables", "-t", "filter", "-I", fw.denyName, "-j", "REJECT", "--reject-with", "icmp6-port-unreachable")
		if err != nil { return err }
		err = fw.execCmd("ip6tables", "-t", "filter", "-I", fw.denyName, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset")
		if err != nil { return err }
	} else {
		err = fw.execCmd("ip6tables", "-t", "filter", "-I", fw.denyName, "-j", "DROP")
		if err != nil { return err }
	}
	err = fw.execCmd("ip6tables", "-t", "filter", "-I", fw.denyName, "-m", "limit", "--limit", "3/min", "-j", "LOG", "--log-prefix", "[PORTKNOB-DENY] ")
	if err != nil { return err }
	fw.execCmd("ip6tables", "-t", "filter", "-N", fw.chainName)
	err = fw.execCmd("ip6tables", "-t", "filter", "-I", fw.chainName, "-j", "RETURN")
	if err != nil { return err }

	// IPv6 redir
	fw.execCmd("ip6tables", "-t", "nat", "-N", fw.chainName)
	err = fw.execCmd("ip6tables", "-t", "nat", "-I", fw.chainName, "-j", "RETURN")
	if err != nil { return err }

	fw.generateRules(fw.conf.Firewall)

	// Activate
	err = fw.execCmd("iptables", "-t", "filter", "-I", "INPUT", "-m", "set", "!", "--match-set", fw.net4Name, "src", "-m", "set", "!", "--match-set", fw.host4Name, "src", "-j", fw.chainName)
	if err != nil { return err }
	err = fw.execCmd("iptables", "-t", "nat", "-I", "OUTPUT", "-m", "set", "!", "--match-set", fw.net4Name, "src", "-m", "set", "!", "--match-set", fw.host4Name, "src", "-m", "addrtype", "--dst-type", "LOCAL", "-j", fw.chainName)
	if err != nil { return err }
	err = fw.execCmd("iptables", "-t", "nat", "-I", "PREROUTING", "-m", "set", "!", "--match-set", fw.net4Name, "src", "-m", "set", "!", "--match-set", fw.host4Name, "src", "-m", "addrtype", "--dst-type", "LOCAL", "-j", fw.chainName)
	if err != nil { return err }
	err = fw.execCmd("ip6tables", "-t", "filter", "-I", "INPUT", "-m", "set", "!", "--match-set", fw.net6Name, "src", "-m", "set", "!", "--match-set", fw.host6Name, "src", "-j", fw.chainName)
	if err != nil { return err }
	err = fw.execCmd("ip6tables", "-t", "nat", "-I", "OUTPUT", "-m", "set", "!", "--match-set", fw.net6Name, "src", "-m", "set", "!", "--match-set", fw.host6Name, "src", "-m", "addrtype", "--dst-type", "LOCAL", "-j", fw.chainName)
	if err != nil { return err }
	err = fw.execCmd("ip6tables", "-t", "nat", "-I", "PREROUTING", "-m", "set", "!", "--match-set", fw.net6Name, "src", "-m", "set", "!", "--match-set", fw.host6Name, "src", "-m", "addrtype", "--dst-type", "LOCAL", "-j", fw.chainName)
	if err != nil { return err }

	fw.doRestore()

	go fw.eventLoop()

	return nil
}

func (fw *firewall) Insert(addr net.IP) (prefix uint, err error) {
	return fw.InsertTimeout(addr, time.Duration(*fw.conf.Daemon.FirewallLifespan) * time.Second, true)
}

func (fw *firewall) InsertTimeout(addr net.IP, timeout time.Duration, updateDB bool) (prefix uint, err error) {
	var setName string
	if addr.To4() != nil {
		prefix = fw.conf.Daemon.IPv4Prefix
		setName = fw.net4Name
		if addr.Mask(net.CIDRMask(int(fw.conf.Daemon.IPv4Prefix), net.IPv4len * 8)).Equal(net.IPv4zero) {
			prefix = 32
			setName = fw.host4Name
		}
	} else {
		prefix = fw.conf.Daemon.IPv6Prefix
		setName = fw.net6Name
		if addr.Mask(net.CIDRMask(int(fw.conf.Daemon.IPv6Prefix), net.IPv6len * 8)).Equal(net.IPv6zero) {
			prefix = 128
			setName = fw.host6Name
		}
	}
	if timeout != 0 {
		err = fw.execCmd("ipset", "-exist", "add", setName, addr.String(), "timeout", strconv.FormatUint(uint64(timeout / time.Second), 10))
	} else {
		err = fw.execCmd("ipset", "-exist", "add", setName, addr.String())
	}
	if err != nil { return }
	if updateDB && timeout != 0 {
		err = fw.cache.Set(addr, time.Now().UTC().Add(timeout))
	}
	return
}

func (fw *firewall) generateRules(rules []configFirewall) {
	for i := 0; i < len(rules); i++ {
		rule := &rules[len(rules) - i - 1]
		var rule_ipv4 bool
		var rule_ipv6 bool
		if rule.Dest == "" {
			rule_ipv4 = true
			rule_ipv6 = true
		} else {
			rule_ipv4 = rule.DestIP.To4() != nil
			rule_ipv6 = !rule_ipv4
		}

		clause_filter := []string {"-t", "filter"}
		clause_nat := []string {"-t", "nat"}
		clause_chain := []string {"-I", fw.chainName}
		var clause_dest []string
		if rule.Dest != "" {
			clause_dest = []string {"-d", rule.Dest}
		}
		clause_tcp := []string {"-p", "tcp", "-m", "tcp"}
		clause_udp := []string {"-p", "udp", "-m", "udp"}
		clause_dport := []string {"--dport", rule.DestPort}
		var clause_comment []string
		if rule.Comment != "" {
			clause_comment = []string {"-m", "comment", "--comment", rule.Comment}
		}
		clause_deny := []string {"-j", fw.denyName}
		clause_redir := []string {"-j", "DNAT", "--to-destination", rule.Redir}
		clause_log := []string {"-m", "limit", "--limit", "3/min", "-j", "LOG", "--log-prefix", "[PORTKNOB-REDIR] "}

		// Deny
		if rule_ipv4 {
			if rule.Proto == "udp" || rule.Proto == "" {
				args := make([]string, 0, 18)
				args = append(args, clause_filter...)
				args = append(args, clause_chain...)
				args = append(args, clause_dest...)
				args = append(args, clause_udp...)
				args = append(args, clause_dport...)
				args = append(args, clause_comment...)
				args = append(args, clause_deny...)
				err := fw.execCmd("iptables", args...)
				if err != nil { log.Println(err) }
			}
			if rule.Proto == "tcp" || rule.Proto == "" {
				args := make([]string, 0, 18)
				args = append(args, clause_filter...)
				args = append(args, clause_chain...)
				args = append(args, clause_dest...)
				args = append(args, clause_tcp...)
				args = append(args, clause_dport...)
				args = append(args, clause_comment...)
				args = append(args, clause_deny...)
				err := fw.execCmd("iptables", args...)
				if err != nil { log.Println(err) }
			}
		}
		if rule_ipv6 {
			if rule.Proto == "udp" || rule.Proto == "" {
				args := make([]string, 0, 18)
				args = append(args, clause_filter...)
				args = append(args, clause_chain...)
				args = append(args, clause_dest...)
				args = append(args, clause_udp...)
				args = append(args, clause_dport...)
				args = append(args, clause_comment...)
				args = append(args, clause_deny...)
				err := fw.execCmd("ip6tables", args...)
				if err != nil { log.Println(err) }
			}
			if rule.Proto == "tcp" || rule.Proto == "" {
				args := make([]string, 0, 18)
				args = append(args, clause_filter...)
				args = append(args, clause_chain...)
				args = append(args, clause_dest...)
				args = append(args, clause_tcp...)
				args = append(args, clause_dport...)
				args = append(args, clause_comment...)
				args = append(args, clause_deny...)
				err := fw.execCmd("ip6tables", args...)
				if err != nil { log.Println(err) }
			}
		}

		// Redirect
		if rule.Redir != "" {
			if rule_ipv4 {
				if rule.Proto == "udp" || rule.Proto == "" {
					args := make([]string, 0, 20)
					args = append(args, clause_nat...)
					args = append(args, clause_chain...)
					args = append(args, clause_dest...)
					args = append(args, clause_udp...)
					args = append(args, clause_dport...)
					args = append(args, clause_comment...)
					args = append(args, clause_redir...)
					err := fw.execCmd("iptables", args...)
					if err != nil { log.Println(err) }
					args = make([]string, 0, 24)
					args = append(args, clause_nat...)
					args = append(args, clause_chain...)
					args = append(args, clause_dest...)
					args = append(args, clause_udp...)
					args = append(args, clause_dport...)
					args = append(args, clause_comment...)
					args = append(args, clause_log...)
					err = fw.execCmd("iptables", args...)
					if err != nil { log.Println(err) }
				}
				if rule.Proto == "tcp" || rule.Proto == "" {
					args := make([]string, 0, 20)
					args = append(args, clause_nat...)
					args = append(args, clause_chain...)
					args = append(args, clause_dest...)
					args = append(args, clause_tcp...)
					args = append(args, clause_dport...)
					args = append(args, clause_comment...)
					args = append(args, clause_redir...)
					err := fw.execCmd("iptables", args...)
					if err != nil { log.Println(err) }
					args = make([]string, 0, 24)
					args = append(args, clause_nat...)
					args = append(args, clause_chain...)
					args = append(args, clause_dest...)
					args = append(args, clause_tcp...)
					args = append(args, clause_dport...)
					args = append(args, clause_comment...)
					args = append(args, clause_log...)
					err = fw.execCmd("iptables", args...)
					if err != nil { log.Println(err) }
				}
			}
			if rule_ipv6 {
				if rule.Proto == "udp" || rule.Proto == "" {
					args := make([]string, 0, 20)
					args = append(args, clause_nat...)
					args = append(args, clause_chain...)
					args = append(args, clause_dest...)
					args = append(args, clause_udp...)
					args = append(args, clause_dport...)
					args = append(args, clause_comment...)
					args = append(args, clause_redir...)
					err := fw.execCmd("ip6tables", args...)
					if err != nil { log.Println(err) }
					args = make([]string, 0, 24)
					args = append(args, clause_nat...)
					args = append(args, clause_chain...)
					args = append(args, clause_dest...)
					args = append(args, clause_udp...)
					args = append(args, clause_dport...)
					args = append(args, clause_comment...)
					args = append(args, clause_log...)
					err = fw.execCmd("ip6tables", args...)
					if err != nil { log.Println(err) }
				}
				if rule.Proto == "tcp" || rule.Proto == "" {
					args := make([]string, 0, 20)
					args = append(args, clause_nat...)
					args = append(args, clause_chain...)
					args = append(args, clause_dest...)
					args = append(args, clause_tcp...)
					args = append(args, clause_dport...)
					args = append(args, clause_comment...)
					args = append(args, clause_redir...)
					err := fw.execCmd("ip6tables", args...)
					if err != nil { log.Println(err) }
					args = make([]string, 0, 24)
					args = append(args, clause_nat...)
					args = append(args, clause_chain...)
					args = append(args, clause_dest...)
					args = append(args, clause_tcp...)
					args = append(args, clause_dport...)
					args = append(args, clause_comment...)
					args = append(args, clause_log...)
					err = fw.execCmd("ip6tables", args...)
					if err != nil { log.Println(err) }
				}
			}
		}
	}
}

func (fw *firewall) eventLoop() {
	cleanupTick := time.Tick(1 * time.Minute)
	for {
		select {
		case <-fw.stopReq:
			fw.Stop()
			return
		case <-cleanupTick:
			fw.doCleanup()
		}
	}
}

func (fw *firewall) Stop() {
	signal.Stop(fw.stopReq)

	// IPv4
	fw.execCmd("iptables", "-t", "filter", "-D", "INPUT", "-m", "set", "!", "--match-set", fw.net4Name, "src", "-m", "set", "!", "--match-set", fw.host4Name, "src", "-j", fw.chainName)
	fw.execCmd("iptables", "-t", "nat", "-D", "OUTPUT", "-m", "set", "!", "--match-set", fw.net4Name, "src", "-m", "set", "!", "--match-set", fw.host4Name, "src", "-m", "addrtype", "--dst-type", "LOCAL", "-j", fw.chainName)
	fw.execCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-m", "set", "!", "--match-set", fw.net4Name, "src", "-m", "set", "!", "--match-set", fw.host4Name, "src", "-m", "addrtype", "--dst-type", "LOCAL", "-j", fw.chainName)

	// IPv6
	fw.execCmd("ip6tables", "-t", "filter", "-D", "INPUT", "-m", "set", "!", "--match-set", fw.net6Name, "src", "-m", "set", "!", "--match-set", fw.host6Name, "src", "-j", fw.chainName)
	fw.execCmd("ip6tables", "-t", "nat", "-D", "OUTPUT", "-m", "set", "!", "--match-set", fw.net6Name, "src", "-m", "set", "!", "--match-set", fw.host6Name, "src", "-m", "addrtype", "--dst-type", "LOCAL", "-j", fw.chainName)
	fw.execCmd("ip6tables", "-t", "nat", "-D", "PREROUTING", "-m", "set", "!", "--match-set", fw.net6Name, "src", "-m", "set", "!", "--match-set", fw.host6Name, "src", "-m", "addrtype", "--dst-type", "LOCAL", "-j", fw.chainName)

	// IPv4 chain
	fw.execCmd("iptables", "-t", "nat", "-F", fw.chainName)
	fw.execCmd("iptables", "-t", "nat", "-X", fw.chainName)
	fw.execCmd("iptables", "-t", "filter", "-F", fw.chainName)
	fw.execCmd("iptables", "-t", "filter", "-X", fw.chainName)
	fw.execCmd("iptables", "-t", "filter", "-F", fw.denyName)
	fw.execCmd("iptables", "-t", "filter", "-X", fw.denyName)

	// IPv6 chain
	fw.execCmd("ip6tables", "-t", "nat", "-F", fw.chainName)
	fw.execCmd("ip6tables", "-t", "nat", "-X", fw.chainName)
	fw.execCmd("ip6tables", "-t", "filter", "-F", fw.chainName)
	fw.execCmd("ip6tables", "-t", "filter", "-X", fw.chainName)
	fw.execCmd("ip6tables", "-t", "filter", "-F", fw.denyName)
	fw.execCmd("ip6tables", "-t", "filter", "-X", fw.denyName)

	// ipset
	fw.execCmd("ipset", "destroy", fw.net4Name)
	fw.execCmd("ipset", "destroy", fw.net6Name)
	fw.execCmd("ipset", "destroy", fw.host4Name)
	fw.execCmd("ipset", "destroy", fw.host6Name)

	fw.cache.Stop()

	os.Exit(0)
}

func (fw *firewall) doCleanup() {
	now := time.Now().UTC()
	fw.cache.Iter(func (addr net.IP, expires time.Time) bool {
		return expires.Sub(now) <= 0
	})
}

func (fw *firewall) doRestore() {
	now := time.Now().UTC()
	fw.cache.Iter(func (addr net.IP, expires time.Time) bool {
		timeout := expires.Sub(now)
		if timeout >= time.Second {
			_, err := fw.InsertTimeout(addr, timeout, false)
			if err != nil { log.Println(err) }
			return false
		} else {
			return true
		}
	})
}

func (fw *firewall) execCmd(name string, arg ...string) error {
	if fw.conf.Daemon.Verbose >= 1 {
		log.Printf("Exec: %s %s\n", name, strings.Join(arg, " "))
	}
	cmd := exec.Command(name, arg...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}
