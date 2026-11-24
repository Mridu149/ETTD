#!/bin/bash
# One-time setup of web content and the TLS certificate. Run from the project folder: ./setup.sh
set -e
cd "$(dirname "$0")"
mkdir -p www certs captures
[ -f www/small.txt ]  || echo "hello" > www/small.txt
[ -f www/index.html ] || echo "<html><body>campus lab</body></html>" > www/index.html
[ -f www/page.html ]  || cp www/index.html www/page.html
[ -f www/video.bin ]  || head -c 2000000 /dev/urandom > www/video.bin
[ -f certs/cert.pem ] || openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout certs/key.pem -out certs/cert.pem -days 60 -subj "/CN=lab" 2>/dev/null
chmod +x gen_benign.sh https_server.py
echo "setup done: www/, certs/ and captures/ are ready"
