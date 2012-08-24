#these two scripts will generate the necessary .pem files for the Cxx tests
#.pem files will be output to ./generated directory
#@see <svn_root>/scripts/upload.bat, this script will upload all the necessary files onto the device
#
#
#call the scripts in the following order:
#first generateCertificates script has to be called

./generateCertificates

#next you can call generateCA2000Certificate:

./generateCA2000Certificate