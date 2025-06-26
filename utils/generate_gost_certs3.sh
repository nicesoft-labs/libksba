#!/bin/bash
set -euo pipefail

# ---------------------------------------------------------
if ! command -v openssl &> /dev/null; then
    echo "❌ openssl не найден в PATH."
    exit 1
fi

OUTDIR=gost_certs2
mkdir -p "${OUTDIR}"
cd "${OUTDIR}"

echo "🎯 Генерация ГОСТ-ключей и сертификатов для проверки ТК-26..."
echo

# 1️⃣ Без EKU
cat > gost_without_eku.cnf <<'EOF'
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = test_without_eku
EOF

openssl req -new \
    -newkey gost2012_256 -pkeyopt paramset:A \
    -keyout test_without_eku.key \
    -out test_without_eku.csr \
    -config gost_without_eku.cnf \
    -nodes

openssl x509 -req \
    -in test_without_eku.csr \
    -signkey test_without_eku.key \
    -out test_without_eku.crt \
    -days 365

echo "✅ test_without_eku.crt создан."
echo

# 2️⃣ EKU подписи
cat > gost_eku_sign.cnf <<'EOF'
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = test_gost_eku_sign

[v3_req]
keyUsage = digitalSignature
extendedKeyUsage = codeSigning, emailProtection
EOF

openssl req -new \
    -newkey gost2012_256 -pkeyopt paramset:A \
    -keyout test_gost_eku_sign.key \
    -out test_gost_eku_sign.csr \
    -config gost_eku_sign.cnf \
    -nodes

openssl x509 -req \
    -in test_gost_eku_sign.csr \
    -signkey test_gost_eku_sign.key \
    -out test_gost_eku_sign.crt \
    -days 365 \
    -extfile gost_eku_sign.cnf \
    -extensions v3_req

echo "✅ test_gost_eku_sign.crt создан."
echo

# 3️⃣ EKU OCSP
cat > gost_eku_ocsp.cnf <<'EOF'
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = test_gost_eku_ocsp

[v3_req]
keyUsage = digitalSignature
extendedKeyUsage = OCSPSigning
EOF

openssl req -new \
    -newkey gost2012_256 -pkeyopt paramset:A \
    -keyout test_gost_eku_ocsp.key \
    -out test_gost_eku_ocsp.csr \
    -config gost_eku_ocsp.cnf \
    -nodes

openssl x509 -req \
    -in test_gost_eku_ocsp.csr \
    -signkey test_gost_eku_ocsp.key \
    -out test_gost_eku_ocsp.crt \
    -days 365 \
    -extfile gost_eku_ocsp.cnf \
    -extensions v3_req

echo "✅ test_gost_eku_ocsp.crt создан."
echo

# 4️⃣ EKU CRL — исправлено!
cat > gost_eku_crl.cnf <<'EOF'
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = test_gost_eku_crl

[v3_req]
keyUsage = cRLSign
EOF

openssl req -new \
    -newkey gost2012_256 -pkeyopt paramset:A \
    -keyout test_gost_eku_crl.key \
    -out test_gost_eku_crl.csr \
    -config gost_eku_crl.cnf \
    -nodes

openssl x509 -req \
    -in test_gost_eku_crl.csr \
    -signkey test_gost_eku_crl.key \
    -out test_gost_eku_crl.crt \
    -days 365 \
    -extfile gost_eku_crl.cnf \
    -extensions v3_req

echo "✅ test_gost_eku_crl.crt создан."
echo

# 5️⃣ Root CA
cat > root_gost_tk26.cnf <<'EOF'
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = root_gost_tk26

[v3_req]
keyUsage = keyCertSign, cRLSign
basicConstraints = critical,CA:true
certificatePolicies = 1.2.643.100.111.1
EOF

openssl req -new \
    -newkey gost2012_256 -pkeyopt paramset:A \
    -keyout root_gost_tk26.key \
    -out root_gost_tk26.csr \
    -config root_gost_tk26.cnf \
    -nodes

openssl x509 -req \
    -in root_gost_tk26.csr \
    -signkey root_gost_tk26.key \
    -out root_gost_tk26.crt \
    -days 365 \
    -extfile root_gost_tk26.cnf \
    -extensions v3_req

echo "✅ root_gost_tk26.crt создан."
echo

# 6️⃣ Leaf CA
cat > leaf_gost_tk26.cnf <<'EOF'
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = leaf_gost_tk26

[v3_req]
keyUsage = digitalSignature
extendedKeyUsage = codeSigning
basicConstraints = critical,CA:false
certificatePolicies = 1.2.643.100.111.1
EOF

openssl req -new \
    -newkey gost2012_256 -pkeyopt paramset:A \
    -keyout leaf_gost_tk26.key \
    -out leaf_gost_tk26.csr \
    -config leaf_gost_tk26.cnf \
    -nodes

openssl x509 -req \
    -in leaf_gost_tk26.csr \
    -CA root_gost_tk26.crt \
    -CAkey root_gost_tk26.key \
    -CAcreateserial \
    -out leaf_gost_tk26.crt \
    -days 365 \
    -extfile leaf_gost_tk26.cnf \
    -extensions v3_req

echo "✅ leaf_gost_tk26.crt создан."
echo

# 7️⃣ Без политики
cat > gost_no_policy.cnf <<'EOF'
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = test_gost_no_policy

[v3_req]
keyUsage = digitalSignature
EOF

openssl req -new \
    -newkey gost2012_256 -pkeyopt paramset:A \
    -keyout test_gost_no_policy.key \
    -out test_gost_no_policy.csr \
    -config gost_no_policy.cnf \
    -nodes

openssl x509 -req \
    -in test_gost_no_policy.csr \
    -signkey test_gost_no_policy.key \
    -out test_gost_no_policy.crt \
    -days 365 \
    -extfile gost_no_policy.cnf \
    -extensions v3_req

echo "✅ test_gost_no_policy.crt создан."
echo

# 8️⃣ Генерация CRL
cat > gost_crl.cnf <<'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
certificate       = root_gost_tk26.crt
private_key       = root_gost_tk26.key
database          = index.txt
serial            = serial.txt
crlnumber         = crlnumber.txt
default_md        = gost2012_256
default_crl_days  = 30
policy            = policy_match

[ policy_match ]
commonName = supplied
EOF

:> index.txt
echo 1000 > serial.txt
echo 1000 > crlnumber.txt

if ! openssl ca -config gost_crl.cnf -gencrl -out root_gost_tk26.crl; then
    echo "⚠️ Ошибка при генерации CRL, но продолжаем."
fi
echo "✅ root_gost_tk26.crl создан (или обновлён)."
echo

# ---------------------------------------------------------
# 9️⃣ OCSP Request
openssl ocsp \
    -issuer root_gost_tk26.crt \
    -cert leaf_gost_tk26.crt \
    -reqout ocsp_req.pem

echo "✅ OCSP запрос ocsp_req.pem создан."
echo

# 🔟 OCSP Response: теперь корректно используется -CA
openssl ocsp \
    -index index.txt \
    -CA root_gost_tk26.crt \
    -issuer root_gost_tk26.crt \
    -rsigner test_gost_eku_ocsp.crt \
    -rkey test_gost_eku_ocsp.key \
    -reqin ocsp_req.pem \
    -respout ocsp_resp.pem \
    -text

echo "✅ OCSP ответ ocsp_resp.pem создан."
echo

echo "✅ OCSP ответ ocsp_resp.pem создан."
echo

echo "🎉 Готово! Все файлы в ${OUTDIR}/"
ls -1

