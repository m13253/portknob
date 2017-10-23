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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
	"os"
	"github.com/gorilla/handlers"
)

type server struct {
	conf		*config
	fw			*firewall
	servemux	*http.ServeMux
}

func newServer(conf *config, fw *firewall) *server {
	s := &server {
		conf:		conf,
		fw:			fw,
		servemux:	http.NewServeMux(),
	}
	s.servemux.HandleFunc(conf.Daemon.HTTPPath, s.handlerFunc)
	return s
}

func (s *server) Start() error {
	return http.ListenAndServe(s.conf.Daemon.Listen, handlers.CombinedLoggingHandler(os.Stdout, s.servemux))
}

func (s *server) handlerFunc(w http.ResponseWriter, r *http.Request) {
	cookie_user, _ := s.cookieString(r, "portknob_user")
	cookie_user, _ = url.QueryUnescape(cookie_user)
	cookie_pass, _ := s.cookieString(r, "portknob_pass")
	cookie_pass, _ = url.QueryUnescape(cookie_pass)

	auth_user, auth_pass, _ := r.BasicAuth()

	match_user, match_pass, ok := "", "", false
	for user, pass := range s.conf.Secrets {
		if (user == auth_user && pass == auth_pass) || (user == cookie_user && pass == cookie_pass) {
			match_user, match_pass, ok = user, pass, true
			break
		}
	}

	if ok {
		clientIP := net.ParseIP(r.Header.Get(s.conf.Daemon.ClientIP))
		if clientIP == nil {
			addr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
			if err == nil {
				clientIP = addr.IP
			}
		}
		if clientIP == nil {
			http.Error(w, "cannot find client's IP address", 500)
			return
		}

		expires := time.Time {}
		if s.conf.Daemon.CookieLifespan != 0 {
			expires = time.Now().Add(time.Duration(s.conf.Daemon.CookieLifespan) * time.Second).UTC()
		}
		http.SetCookie(w, &http.Cookie {
			Name:		"portknob_user",
			Value:		url.QueryEscape(match_user),
			Path:		s.conf.Daemon.HTTPPath,
			Expires:	expires,
			HttpOnly:	true,
		})
		http.SetCookie(w, &http.Cookie {
			Name:		"portknob_pass",
			Value:		url.QueryEscape(match_pass),
			Path:		s.conf.Daemon.HTTPPath,
			Expires:	expires,
			HttpOnly:	true,
		})

		prefix := uint(0)
		if clientIP.To4() != nil {
			prefix = s.conf.Daemon.IPv4Prefix
		} else {
			prefix = s.conf.Daemon.IPv6Prefix
		}
		clientCIDR := fmt.Sprintf("%s/%d", clientIP.String(), prefix)
		err := s.fw.Insert(clientCIDR)
		if err != nil {
			http.Error(w, "cannot update firewall", 500)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write([]byte(fmt.Sprintf("<!DOCTYPE html><html><head><script language=\"javascript\">window.alert(\"Login succeeded for \" + %q);window.history.back();window.close();</script></head></html>\r\n", clientCIDR)))
	} else {
		w.Header().Set("WWW-Authenticate", "Basic")
		http.Error(w, "Access Unauthorized", 401)
	}
}

func (s *server) cookieString(r *http.Request, name string) (string, error) {
	c, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}
