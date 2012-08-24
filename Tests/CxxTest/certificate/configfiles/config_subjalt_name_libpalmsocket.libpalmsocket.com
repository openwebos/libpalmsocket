#scritGenerate script uses this configfile to generate private keys

[ req ]
default_bits           = 1024
default_keyfile        = keyfile.pem
distinguished_name     = req_distinguished_name
attributes             = req_attributes
prompt                 = no
#output_password        = 
#req_extensions         = v3_req

[ req_distinguished_name ]
C                      = RO
ST                     = Test State or Province
L                      = Test Locality
O                      = Organization Name
OU                     = Organizational Unit Name
#Make sure you enter the FQDN ("Fully Qualified Domain Name") of the server when OpenSSL prompts you for the "CommonName", i.e. when you generate a CSR for a website which will be later accessed via https://www.foo.dom/, enter "www.foo.dom" here. You can see the details of this CSR via the command 
CN                     = localhost
emailAddress           = test@email.address

[ req_attributes ]
#challengePassword              = 
#challengePassword_min          = 0
#challengePassword_max          = 0

[ v3_req ]
#basicConstraints        = CA:FALSE
#keyUsage                = nonRepudiation, digitalSignature, keyEncipherment

# Verisign managed PKI, does not yet support subjectAltName in CSRs, instead
# they prompt for these in the enrollment form...
# If your CA support SAN CSRs, uncomment below.
subjectAltName          = @alt_names

[ alt_names ]
DNS = libpalmsocket.libpalmsocket.com



