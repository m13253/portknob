portknob -- Port knocking daemon with web interface
===================================================

## Introduction

Portknob operates on Linux firewall to protect your network services from being accessed by unauthorized people.

It provides a web interface for authorization with username and password.

## Usage

Imagine you have an SSH service on port 22. You configure Portknob to protect port 22.

When unauthorized people try to connect to your port 22, they will get a "connection refused" error.

While you can first visit the HTTPS service at port 443, typing in your username and password. Portpub will then add you to the firewall whitelist, allowing you to connect to port 22 afterwards.

## Easy start

Install [Go](https://golang.org), at least version 1.8.

First create an empty directory, used for `$GOPATH`:

    mkdir ~/gopath
    export GOPATH=~/gopath

To build the program, type:

    make

To install Portknob as Systemd services, type:

    sudo make install

Then edit the configuration file at `/etc/portknob.conf`.

Start and enable the service:

    sudo systemctl start portknob
    sudo systemctl enable portknob

Install an HTTP server and configure it as below:

### Caddy configuration example

[Caddy](https://caddyserver.com) is recommended since it provides automatic [Let's Encrypt](https://letsencrypt.org) integration.

    https://my-example-domain-name.com {
        proxy / http://[::1]:706 {
            transparent
        }
    }

### Nginx configuration example

[Nginx](https://nginx.org) is also supported.

    server {
        server_name my-example-domain-name.com;
        listen 80;
        listen 443 ssl http2;
        location / {
            if ( $scheme = http ) {
                rewrite ^ https://$server_name$request_uri? permanent;
            }
            proxy_set_header Host      $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_pass       http://[::1]:706;
        }
    }

## License

This program is licensed under GPL version 3. See [COPYING](COPYING) for details.
