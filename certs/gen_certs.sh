#!/usr/bin/env bash
# Generate a private CA, a broker cert, per-device client certs (CN = device id)
# and a "rogue" cert signed by a different CA (used to show mTLS rejection).
# Lab-only keys: never reuse these outside this project.
set -euo pipefail
cd "$(dirname "$0")"
rm -f ./*.crt ./*.key ./*.csr ./*.srl ./*.ext

new_ca() {  # name
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=$1" \
    -keyout "$1.key" -out "$1.crt" 2>/dev/null
}

issue() {  # name ca ext
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$1" -keyout "$1.key" -out "$1.csr" 2>/dev/null
  printf "%s\n" "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial \
    -days 365 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
  rm -f "$1.csr" "$1.ext"
}

new_ca ca
new_ca rogue-ca
issue broker ca "subjectAltName=IP:127.0.0.1,DNS:localhost
extendedKeyUsage=serverAuth"
for dev in pump-01 pump-02 pump-03 detector; do
  issue "$dev" ca "extendedKeyUsage=clientAuth"
done
issue rogue rogue-ca "extendedKeyUsage=clientAuth"
rm -f ./*.srl
chmod 600 ./*.key
echo "certs written to $(pwd)"
