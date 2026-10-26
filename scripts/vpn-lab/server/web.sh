#!/bin/sh
# The test page (10.99.0.10:80): says which VPN server the request came through.
set -eu
mkdir -p /www/cgi-bin
cp /lab/server/index.cgi /www/cgi-bin/index.cgi
chmod 755 /www/cgi-bin/index.cgi
printf '<meta http-equiv="refresh" content="0;url=/cgi-bin/index.cgi">\n' >/www/index.html
exec httpd -f -v -p 80 -h /www
