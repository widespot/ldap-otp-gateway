CERTS_PATH=${CERTS_PATH:-"./certs"}
TLS_CA_CERT_FILE_PATH=${TLS_CA_CERT_FILE_PATH:-"${CERTS_PATH}/ca.crt.pem"}
TLS_CA_CERT_KEY_FILE_PATH=${TLS_CA_CERT_KEY_FILE_PATH:-"${CERTS_PATH}/ca.key.pem"}
TLS_CERT_FILE_PATH=${TLS_CERT_FILE_PATH:-"${CERTS_PATH}/server.crt.pem"}
TLS_CERT_KEY_FILE_PATH=${TLS_CERT_KEY_FILE_PATH:-"${CERTS_PATH}/server.key.pem"}
TLS_CERT_CSR_FILE_PATH=${TLS_CERT_CSR_FILE_PATH:-"${CERTS_PATH}/server.csr.pem"}
TLS_CERT_COUNTRY=${TLS_CERT_COUNTRY:="BE"}
TLS_CERT_STATE=${TLS_CERT_STATE:="Brussels"}
TLS_CERT_CITY=${TLS_CERT_CITY:="Brussels"}
TLS_CERT_COMPANY=${TLS_CERT_COMPANY:="Example"}
TLS_CERT_ORGANIZATION_UNIT=${TLS_CERT_ORGANIZATION_UNIT:="IT"}
TLS_CERT_COMMON_NAME=${TLS_CERT_COMMON_NAME:="localhost"}

mkdir -p $CERTS_PATH

echo -n " - CA private key (${TLS_CA_CERT_KEY_FILE_PATH}) ..."
openssl genrsa 2048 > "${TLS_CA_CERT_KEY_FILE_PATH}"
echo " done!"

SUBJECT="/C=${TLS_CERT_COUNTRY}/ST=${TLS_CERT_STATE}/L=${TLS_CERT_CITY}/O=${TLS_CERT_COMPANY}/OU=${TLS_CERT_ORGANIZATION_UNIT}/CN=${TLS_CERT_COMMON_NAME}"
echo -n " - CA cert (${TLS_CA_CERT_FILE_PATH}) for ${SUBJECT} ..."
openssl req -new -x509 -nodes -days 365000 \
  -key "${TLS_CA_CERT_KEY_FILE_PATH}" \
  -out "${TLS_CA_CERT_FILE_PATH}" \
  -subj "${SUBJECT}"
echo " done!"

echo -n " - Server private key (${TLS_CERT_KEY_FILE_PATH}) ..."
openssl genrsa 2048 > "${TLS_CERT_KEY_FILE_PATH}"
echo " done!"

echo -n " - Server signing request (${TLS_CERT_CSR_FILE_PATH}) for ${SUBJECT} ..."
openssl req -new \
  -key "${TLS_CERT_KEY_FILE_PATH}" \
  -out "${TLS_CERT_CSR_FILE_PATH}" \
  -subj "${SUBJECT}"
echo " done!"
echo -n " - Server certificate (${TLS_CERT_FILE_PATH}) ..."
openssl x509 -req -days 365000 -set_serial 01 \
   -in "${TLS_CERT_CSR_FILE_PATH}" \
   -out "${TLS_CERT_FILE_PATH}" \
   -CA "${TLS_CA_CERT_FILE_PATH}" \
   -CAkey "${TLS_CA_CERT_KEY_FILE_PATH}" 2> /dev/null
echo " done!"
