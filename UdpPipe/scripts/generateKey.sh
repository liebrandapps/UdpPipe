openssl genrsa -out private.key 1024
openssl pkcs8 -topk8 -inform pem -in private.key -outform pem -nocrypt -out private.pem
openssl req -new -x509 -key private.key -out publickey.cer -days 365
openssl x509 -inform pem -in publickey.cer -pubkey -noout > publickey.pem
mkdir ../key
mv private.pem ../key
mv publickey.cer ../key
mv publickey.pem ../key