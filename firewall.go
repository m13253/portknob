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
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

type firewall struct {
	conf		*config
	chainName	string
	listName	string
	stopReq		chan os.Signal
	insert4Req	chan string
	remove4Req	chan string
	insert6Req	chan string
	remove6Req	chan string
}

func newFirewall(conf *config) *firewall {
	fw := &firewall {
		conf:		conf,
		chainName:	conf.Daemon.FirewallChainName,
		listName:	conf.Daemon.FirewallChainName + "-list",
		stopReq:	make(chan os.Signal, 1),
		insert4Req:	make(chan string),
		remove4Req:	make(chan string),
		insert6Req:	make(chan string),
		remove6Req:	make(chan string),
	}
	return fw
}

func (fw *firewall) Start() error {
	signal.Notify(fw.stopReq, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	// IPv4
	err := fw.execCmd("iptables", "-N", fw.listName)
	if err != nil { return err }
	if fw.conf.Daemon.FirewallDenyMethod == "reject" {
		err = fw.execCmd("iptables", "-I", fw.listName, "-j", "REJECT", "--reject-with", "icmp-port-unreachable")
		if err != nil { return err }
		err = fw.execCmd("iptables", "-I", fw.listName, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset")
		if err != nil { return err }
	} else {
		err = fw.execCmd("iptables", "-I", fw.listName, "-j", "DROP")
		if err != nil { return err }
	}
	err = fw.execCmd("iptables", "-N", fw.chainName)
	if err != nil { return err }
	err = fw.execCmd("iptables", "-I", fw.chainName, "-j", "RETURN")
	if err != nil { return err }

	// IPv6
	err = fw.execCmd("ip6tables", "-N", fw.listName)
	if err != nil { return err }
	if fw.conf.Daemon.FirewallDenyMethod == "reject" {
		err = fw.execCmd("ip6tables", "-I", fw.listName, "-j", "REJECT", "--reject-with", "icmp6-port-unreachable")
		if err != nil { return err }
		err = fw.execCmd("ip6tables", "-I", fw.listName, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset")
		if err != nil { return err }
	} else {
		err = fw.execCmd("ip6tables", "-I", fw.listName, "-j", "DROP")
		if err != nil { return err }
	}
	err = fw.execCmd("ip6tables", "-N", fw.chainName)
	if err != nil { return err }
	err = fw.execCmd("ip6tables", "-I", fw.chainName, "-j", "RETURN")
	if err != nil { return err }

	fw.generateFilters(fw.conf.Firewall)

	// Apply
	err = fw.execCmd("iptables", "-I", "INPUT", "-j", fw.chainName)
	if err != nil { return err }
	err = fw.execCmd("ip6tables", "-I", "INPUT", "-j", fw.chainName)
	if err != nil { return err }

	go fw.acceptRequests()
	return nil
}

func (fw *firewall) Insert(addr string) error {
	slash := strings.IndexByte(addr, '/')
	if slash < 0 {
		slash = len(addr)
	}
	ip := net.ParseIP(addr[:slash])
	if ip == nil {
		return &net.ParseError {
			Type: "IP address",
			Text: addr,
		}
	}
	if ip.To4() != nil {
		fw.insert4Req <- addr
	} else {
		fw.insert6Req <- addr
	}
	return nil
}

func (fw *firewall) Remove(addr string) error {
	slash := strings.IndexByte(addr, '/')
	if slash < 0 {
		slash = len(addr)
	}
	ip := net.ParseIP(addr[:slash])
	if ip == nil {
		return &net.ParseError {
			Type: "IP address",
			Text: addr,
		}
	}
	if ip.To4() != nil {
		fw.remove4Req <- addr
	} else {
		fw.remove6Req <- addr
	}
	return nil
}

func (fw *firewall) generateFilters(rules []configFirewall) {
	var err error

	for i := 0; i < len(rules); i++ {
		rule := &rules[len(rules) - i - 1]
		rule_ipv4 := false
		rule_ipv6 := true
		if rule.Dest == "" {
			rule_ipv4 = true
			rule_ipv6 = true
		} else {
			rule_ipv4 = rule.DestIP.To4() != nil
			rule_ipv6 = !rule_ipv4
		}

		clause_dest := []string(nil)
		if rule.Dest != "" {
			clause_dest = []string {"-d", rule.Dest}
		}
		clause_comment := []string(nil)
		if rule.Comment != "" {
			clause_comment = []string {"-m", "comment", "--comment", rule.Comment}
		}

		if rule_ipv4 {
			if rule.Proto == "udp" || rule.Proto == "" {
				args := make([]string, 0, 12)
				args = append(args, "-I", fw.chainName)
				args = append(args, clause_dest...)
				args = append(args, "-p", "udp", "-m", "udp", "--dport", rule.DestPort)
				args = append(args, clause_comment...)
				args = append(args, "-j", fw.listName)
				err = fw.execCmd("iptables", args...)
				if err != nil { log.Println(err) }
			}
			if rule.Proto == "tcp" || rule.Proto == "" {
				args := make([]string, 0, 16)
				args = append(args, "-I", fw.chainName)
				args = append(args, clause_dest...)
				args = append(args, "-p", "tcp", "-m", "tcp", "--dport", rule.DestPort)
				args = append(args, clause_comment...)
				args = append(args, "-j", fw.listName)
				err = fw.execCmd("iptables", args...)
				if err != nil { log.Println(err) }
			}
		}
		if rule_ipv6 {
			if rule.Proto == "udp" || rule.Proto == "" {
				args := make([]string, 0, 16)
				args = append(args, "-I", fw.chainName)
				args = append(args, clause_dest...)
				args = append(args, "-p", "udp", "-m", "udp", "--dport", rule.DestPort)
				args = append(args, clause_comment...)
				args = append(args, "-j", fw.listName)
				err = fw.execCmd("ip6tables", args...)
				if err != nil { log.Println(err) }
			}
			if rule.Proto == "tcp" || rule.Proto == "" {
				args := make([]string, 0, 16)
				args = append(args, "-I", fw.chainName)
				args = append(args, clause_dest...)
				args = append(args, "-p", "tcp", "-m", "tcp", "--dport", rule.DestPort)
				args = append(args, clause_comment...)
				args = append(args, "-j", fw.listName)
				err = fw.execCmd("ip6tables", args...)
				if err != nil { log.Println(err) }
			}
		}
	}
}

func (fw *firewall) acceptRequests() {
	for {
		select {
		case <-fw.stopReq:
			fw.doStop()
			return
		case addr := <-fw.remove4Req:
			err := fw.execCmd("iptables", "-D", fw.listName, "-s", addr, "-j", "RETURN")
			if err != nil { log.Println(err) }
		case addr := <-fw.insert4Req:
			err := fw.execCmd("iptables", "-I", fw.listName, "-s", addr, "-j", "RETURN")
			if err != nil { log.Println(err) }
		case addr := <-fw.remove6Req:
			err := fw.execCmd("ip6tables", "-D", fw.listName, "-s", addr, "-j", "RETURN")
			if err != nil { log.Println(err) }
		case addr := <-fw.insert6Req:
			err :=fw.execCmd("ip6tables", "-I", fw.listName, "-s", addr, "-j", "RETURN")
			if err != nil { log.Println(err) }
		}
	}
}

func (fw *firewall) doStop() {
	signal.Stop(fw.stopReq)

	fw.execCmd("iptables", "-D", "INPUT", "-j", fw.chainName)
	fw.execCmd("ip6tables", "-D", "INPUT", "-j", fw.chainName)

	// IPv4
	fw.execCmd("iptables", "-F", fw.chainName)
	fw.execCmd("iptables", "-X", fw.chainName)
	fw.execCmd("iptables", "-F", fw.listName)
	fw.execCmd("iptables", "-X", fw.listName)

	// IPv6
	fw.execCmd("ip6tables", "-F", fw.chainName)
	fw.execCmd("ip6tables", "-X", fw.chainName)
	fw.execCmd("ip6tables", "-F", fw.listName)
	fw.execCmd("ip6tables", "-X", fw.listName)

	os.Exit(0)
}

func (fw *firewall) execCmd(name string, arg ...string) error {
	//log.Printf("Exec: %s %s\n", name, strings.Join(arg, " "))
	cmd := exec.Command(name, arg...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}
