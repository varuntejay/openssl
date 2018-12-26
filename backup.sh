#!/bin/bash
###############################################################################
#
# Name    : generate.s
# Purpose : To generate child crypto material for the given root certificates
#
# Author  : Varun Yadavalli
################################################################################

export rootCert=$1
export rootKey=$2
export confFileTemplate=$3
export configTemplate=$4
export confFile=$PWD/openssl.cnf

function generateKey () {
	typeset keyFile=$1
	typeset tempKeyFile=$keyFile".temp"
	
	openssl ecparam -name prime256v1 -genkey -noout -out $tempKeyFile
	if 	[[ $? -ne 0 ]] ; then
		echo "Private key creation failed : $keyFile"
		exit 4
	fi
	openssl pkcs8 -topk8 -nocrypt -in $tempKeyFile -out $keyFile
	if 	[[ $? -ne 0 ]] ; then
		echo "Private key PKCS#8 format conversion failed : $keyFile"
		exit 4
	fi
	rm $tempKeyFile
}

function generateCSR () {
	typeset keyFile=$1
	typeset CN=$2
	typeset rootCaCert=$3
	typeset rootCaKey=$4
	typeset csrFile=$5
	typeset caFlag=$6
	typeset org=$7
	typeset orgUnit=$8
	typeset extension=$9

	cp $confFileTemplate $confFile
	sed -i "s,%%root_key,$rootCaCert," $confFile
	sed -i "s,%%root_cert,$rootCaKey," $confFile
	sed -i "s,%%caFlag,$caFlag," $confFile

	if [[ $org != "NULL" && $orgUnit != "NULL" ]] ; then
		openssl req -new -config $confFile -extensions $extension -x509 -key $keyFile -out $csrFile -subj "/C=US/ST=California/L=San Francisco/CN=$CN/O=$org/OU=$orgUnit"
		RC=$?
	elif [[ $org != "NULL" ]] ; then
		openssl req -new -config $confFile -extensions $extension -x509 -key $keyFile -out $csrFile -subj "/C=US/ST=California/L=San Francisco/CN=$CN/O=$org" 
		RC=$?
	elif [[ $orgUnit != "NULL" ]] ; then
		openssl req -new -config $confFile -extensions $extension -x509 -key $keyFile -out $csrFile -subj "/C=US/ST=California/L=San Francisco/CN=$CN/OU=$orgUnit" 
		RC=$?
	else
		openssl req -new -config $confFile -extensions $extension -x509 -key $keyFile -out $csrFile -subj "/C=US/ST=California/L=San Francisco/CN=$CN" 
		RC=$?
	fi
	
	if 	[[ $RC -ne 0 ]] ; then
		echo "CSR creation failed : $csrFile"
		exit 4
	fi
}

function generateCert () {
	typeset csrFile=$1
	typeset rootCaCert=$2
	typeset rootCaKey=$3
	typeset certFile=$4

	# echo "$rootCaCert"
	# echo "$rootCaKey"
    # echo "openssl x509 -days 365 -CAcreateserial -CAserial ca.seq -in $csrFile -CA $rootCaCert -CAkey $rootCaKey -out $certFile"
	openssl x509 -days 365 -CAcreateserial -CAserial ca.seq -in $csrFile -CA $rootCaCert -CAkey $rootCaKey -out $certFile > /dev/null
	if 	[[ $? -ne 0 ]] ; then
		echo "Certificate creation failed : $certFile"
		exit 4
	fi
}

function getSKI () {
	ski=$(openssl x509 -noout -text -in $1 | grep -A1 "Subject Key Identifier"  | awk  -F 'X509v3 Subject Key Identifier:' '{print tolower($1)}' | sed 's/://g')
	if [[ $? -ne 0 ]] ; then
		echo "Extracting Subject key identifier from cert $1 failed!"
	fi
	echo $ski
}

function getAKI () {
	aki=$(openssl x509 -in $1 -text | awk '/keyid/ {gsub(/ *keyid:|:/,"",$1);print tolower($0)}')
	if [[ $? -ne 0 ]] ; then
		echo "Extracting Application key identifier from cert $1 failed!"
	fi
	echo $aki
}

function createCerts () {
	typeset CN=$1
	typeset signCertFile=$2
	typeset signKeyFile=$3
	typeset csrFile=$4
	typeset certFile=$5
	typeset keyFile=$6
	typeset dir=$7
	typeset caFlag=$8
	typeset org=$9
	typeset orgUnit=${10}
	typeset extension=${11}
	
	generateKey $keyFile
	generateCSR $keyFile $CN $signCertFile $signKeyFile $csrFile $caFlag $org $orgUnit $extension
	generateCert $csrFile $signCertFile $signKeyFile $certFile 

	if [[ $extension == "v3_intermediate_ca" ]] ; then
		mv $keyFile $dir/$(getSKI $certFile)"_sk"
	elif [[ $extension == "usr_cert" ]] ; then 
		mv $keyFile $dir/$(getAKI $certFile)"_sk"
	fi
	
	# Remove temporary files
	# rm $csrFile
}

function generateOrdererCerts () {
	typeset ordererDir=$1
	typeset signCert=$2
	typeset signKey=$3
	typeset CN=$4

	# generate ca cert from root cert file
	# typeset newCaCsr=$PWD/ca.$CN-csr.pem
	# typeset newCaCert=$PWD/ca.$CN-cert.pem
	# typeset newCaKey=$PWD/ca.$CN-key.pem

	# createCerts ca.$CN $signCert $signKey $newCaCsr $newCaCert $newCaKey $PWD "true" $CN
	# newCaKey=$PWD/$(getAKI $newCaCert)"_sk"
	
	# # generate tls ca cert from root cert file
	# typeset newTlscaCsr=$PWD/tlsca.$CN-csr.pem
	# typeset newTlscaCert=$PWD/tlsca.$CN-cert.pem
	# typeset newTlscaKey=$PWD/tlsca.$CN-key.pem

	# createCerts tlsca.$CN $signCert $signKey $newTlscaCsr $newTlscaCert $newTlscaKey $PWD "true" $CN
	# newTlscaKey=$PWD/$(getAKI $newTlscaCert)"_sk"

	typeset workDir=$1/$CN
	typeset caDir=$workDir/ca
	typeset tlscaDir=$workDir/tlsca
	typeset orderersDir=$workDir/orderers
	typeset userDir=$workDir/users
	typeset mspDir=$workDir/msp

	mkdir -p $workDir $caDir $tlscaDir $orderersDir $usersDir $mspDir

	# generate intermediary1 ca cert from root cert file
	typeset caCsr=$caDir/ca.$CN-csr.pem
	typeset caCert=$caDir/ca.$CN-cert.pem
	typeset caKey=$caDir/ca.$CN-key.pem

	# signCert=$newCaCert
	# signKey=$newCaKey
	createCerts ca.$CN $signCert $signKey $caCsr $caCert $caKey $caDir "true" "NULL" "NULL" "v3_intermediate_ca"
	caKey=$caDir/$(getSKI $caCert)"_sk"
	
	# generate intermediary1 ca cert from root cert file
	typeset tlscaCsr=$tlscaDir/tlsca.$CN-csr.pem
	typeset tlscaCert=$tlscaDir/tlsca.$CN-cert.pem
	typeset tlscaKey=$tlscaDir/tlsca.$CN-key.pem

	# signCert=$newTlscaCert
	# signKey=$newTlscaKey
	createCerts tlsca.$CN $signCert $signKey $tlscaCsr $tlscaCert $tlscaKey $tlscaDir "true" "NULL" "NULL" "v3_intermediate_ca"
	tlscaKey=$tlscaDir/$(getSKI $tlscaCert)"_sk"

	typeset usersDir=$userDir/"Admin@"$CN
	typeset usersTlsDir=$usersDir"/tls"
	typeset usersMspDir=$usersDir"/msp"
	typeset usersMspTlscaDir=$usersDir"/msp/tlscacerts"
	typeset usersMspSignDir=$usersDir"/msp/signcerts"
	typeset usersMspKeyDir=$usersDir"/msp/keystore"
	typeset usersMspCaDir=$usersDir"/msp/cacerts"
	typeset usersMspAdminDir=$usersDir"/msp/admincerts"

	mkdir -p $usersDir $usersTlsDir $usersMspDir $usersMspTlscaDir $usersMspSignDir $usersMspKeyDir $usersMspCaDir $usersMspCaDir $usersMspAdminDir

	# generate TLS Admin user certs
	typeset adminTlscaCsr=$usersTlsDir/Admin@$CN-csr.pem
	typeset adminTlscaCert=$usersTlsDir/Admin@$CN-cert.pem
	typeset adminTlscaKey=$usersTlsDir/Admin@$CN-key.pem

	createCerts "Admin@$CN" $tlscaCert $tlscaKey $adminTlscaCsr $adminTlscaCert $adminTlscaKey $usersTlsDir "false" "NULL" "NULL" "usr_cert"
	adminTlscaKey=$usersTlsDir/$(getAKI $adminTlscaCert)"_sk"
	
	mv $adminTlscaCert $usersTlsDir/server.crt
	mv $adminTlscaKey $usersTlsDir/server.key
	cp $tlscaCert $usersTlsDir/ca.crt
	
	# generate CA Admin user certs
	typeset adminCaCsr=$usersMspAdminDir/Admin@$CN-csr.pem
	typeset adminCaCert=$usersMspAdminDir/Admin@$CN-cert.pem
	typeset adminCaKey=$usersMspAdminDir/Admin@$CN-key.pem

	createCerts "Admin@$CN" $caCert $caKey $adminCaCsr $adminCaCert $adminCaKey $usersMspAdminDir "false" "NULL" "NULL" "usr_cert"
	adminCaKey=$usersMspAdminDir/$(getAKI $adminCaCert)"_sk"
	
	cp $tlscaCert $usersMspTlscaDir
	cp $caCert $usersMspCaDir
	cp $adminCaCert $usersMspSignDir
	mv $adminCaKey $usersMspKeyDir

	typeset mspTlscacertsDir=$mspDir"/tlscacerts"
	typeset mspCacertsDir=$mspDir"/cacerts"
	typeset mspAdmincertsDir=$mspDir"/admincerts"

	mkdir -p $mspTlscacertsDir $mspCacertsDir $mspAdmincertsDir
	cp $tlscaCert $mspTlscacertsDir
	cp $caCert $mspCacertsDir
	cp $adminCaCert $mspAdmincertsDir

	#typeset mspConfig=$mspDir/config.yaml
	#cp $configTemplate $mspConfig
	#sed -i "s,%%cacerts,"cacerts/"$(basename $caCert),g" $mspConfig

	typeset ordererDir=$orderersDir/orderer.$CN
	typeset ordererTlsDir=$ordererDir"/tls"
	typeset ordererMspDir=$ordererDir"/msp"
	typeset ordererMspTlscaDir=$ordererDir"/msp/tlscacerts"
	typeset ordererMspSignDir=$ordererDir"/msp/signcerts"
	typeset ordererMspKeyDir=$ordererDir"/msp/keystore"
	typeset ordererMspCaDir=$ordererDir"/msp/cacerts"
	typeset ordererMspAdminDir=$ordererDir"/msp/admincerts"

	mkdir -p $ordererDir $ordererTlsDir $ordererMspDir $ordererMspTlscaDir $ordererMspSignDir $ordererMspKeyDir $ordererMspCaDir $ordererMspCaDir $ordererMspAdminDir
	

	# generate TLS Admin user certs
	typeset ordererTlscaCsr=$ordererMspTlscaDir/orderer.$CN-csr.pem
	typeset ordererTlscaCert=$ordererMspTlscaDir/orderer.$CN-cert.pem
	typeset ordererTlscaKey=$ordererMspTlscaDir/orderer.$CN-key.pem

	createCerts "orderer.$CN" $tlscaCert $tlscaKey $ordererTlscaCsr $ordererTlscaCert $ordererTlscaKey $ordererMspTlscaDir "false" "NULL" "NULL" "usr_cert"
	ordererTlscaKey=$ordererMspTlscaDir/$(getAKI $ordererTlscaCert)"_sk"

	mv $ordererTlscaCert $ordererTlsDir/server.crt
	mv $ordererTlscaKey $ordererTlsDir/server.key
	cp $tlscaCert $ordererTlsDir/ca.crt
	
	# generate CA Admin user certs
	typeset ordererCaCsr=$ordererMspCaDir/orderer.$CN-csr.pem
	typeset ordererCaCert=$ordererMspCaDir/orderer.$CN-cert.pem
	typeset ordererCaKey=$ordererMspCaDir/orderer.$CN-key.pem

	createCerts "orderer.$CN" $caCert $caKey $ordererCaCsr $ordererCaCert $ordererCaKey $ordererMspCaDir "false" "NULL" "NULL" "usr_cert"
	ordererCaKey=$ordererMspCaDir/$(getAKI $ordererCaCert)"_sk"

	cp $tlscaCert $ordererMspTlscaDir
	cp $caCert $ordererMspCaDir
	mv $ordererCaCert $ordererMspSignDir
	mv $ordererCaKey $ordererMspKeyDir
	cp $adminCaCert $ordererMspAdminDir
}

function generatePeerCerts () {
	typeset peerDir=$1
	typeset signCert=$2
	typeset signKey=$3
	typeset CN=$4
	typeset peerCount=$5
	typeset userCount=$6

	# # generate ca cert from root cert file
	# typeset newCaCsr=$PWD/ca.$CN-csr.pem
	# typeset newCaCert=$PWD/ca.$CN-cert.pem
	# typeset newCaKey=$PWD/ca.$CN-key.pem

	# createCerts ca.$CN $signCert $signKey $newCaCsr $newCaCert $newCaKey $PWD "true" $CN
	# newCaKey=$PWD/$(getAKI $newCaCert)"_sk"
	
	# # generate tls ca cert from root cert file
	# typeset newTlscaCsr=$PWD/tlsca.$CN-csr.pem
	# typeset newTlscaCert=$PWD/tlsca.$CN-cert.pem
	# typeset newTlscaKey=$PWD/tlsca.$CN-key.pem

	# createCerts tlsca.$CN $signCert $signKey $newTlscaCsr $newTlscaCert $newTlscaKey $PWD "true" $CN
	# newTlscaKey=$PWD/$(getAKI $newTlscaCert)"_sk"

	typeset workDir=$1/$CN
	typeset caDir=$workDir/ca
	typeset tlscaDir=$workDir/tlsca
	typeset peerDir=$workDir/peers
	typeset userDir=$workDir/users
	typeset mspDir=$workDir/msp
	
	mkdir -p $workDir $caDir $tlscaDir $peersDir $usersDir $mspDir

	# generate intermediary1 ca cert from root cert file
	typeset caCsr=$caDir/ca.$CN-csr.pem
	typeset caCert=$caDir/ca.$CN-cert.pem
	typeset caKey=$caDir/ca.$CN-key.pem

	# signCert=$newCaCert
	# signKey=$newCaKey

	createCerts ca.$CN $signCert $signKey $caCsr $caCert $caKey $caDir "true" "NULL" "NULL" "v3_intermediate_ca"
	caKey=$caDir/$(getSKI $caCert)"_sk"
	
	# generate intermediary1 ca cert from root cert file
	typeset tlscaCsr=$tlscaDir/tlsca.$CN-csr.pem
	typeset tlscaCert=$tlscaDir/tlsca.$CN-cert.pem
	typeset tlscaKey=$tlscaDir/tlsca.$CN-key.pem

	# signCert=$newTlscaCert
	# signKey=$newTlscaKey

	createCerts tlsca.$CN $signCert $signKey $tlscaCsr $tlscaCert $tlscaKey $tlscaDir "true" "NULL" "NULL" "v3_intermediate_ca"
	tlscaKey=$tlscaDir/$(getSKI $tlscaCert)"_sk"

	typeset usersDir=$userDir/"Admin@"$CN
	typeset usersTlsDir=$usersDir"/tls"
	typeset usersMspDir=$usersDir"/msp"
	typeset usersMspTlscaDir=$usersDir"/msp/tlscacerts"
	typeset usersMspSignDir=$usersDir"/msp/signcerts"
	typeset usersMspKeyDir=$usersDir"/msp/keystore"
	typeset usersMspCaDir=$usersDir"/msp/cacerts"
	typeset usersMspAdminDir=$usersDir"/msp/admincerts"

	mkdir -p $usersDir $usersTlsDir $usersMspDir $usersMspTlscaDir $usersMspSignDir $usersMspKeyDir $usersMspCaDir $usersMspCaDir $usersMspAdminDir

	# generate TLS Admin user certs
	typeset adminTlscaCsr=$usersTlsDir/Admin@$CN-csr.pem
	typeset adminTlscaCert=$usersTlsDir/Admin@$CN-cert.pem
	typeset adminTlscaKey=$usersTlsDir/Admin@$CN-key.pem

	createCerts "Admin@$CN" $tlscaCert $tlscaKey $adminTlscaCsr $adminTlscaCert $adminTlscaKey $usersTlsDir "false" "NULL" "NULL" "usr_cert"
	adminTlscaKey=$usersTlsDir/$(getAKI $adminTlscaCert)"_sk"
	
	mv $adminTlscaCert $usersTlsDir/client.crt
	mv $adminTlscaKey $usersTlsDir/client.key
	cp $tlscaCert $usersTlsDir/ca.crt
	
	# generate CA Admin user certs
	typeset adminCaCsr=$usersMspAdminDir/Admin@$CN-csr.pem
	typeset adminCaCert=$usersMspAdminDir/Admin@$CN-cert.pem
	typeset adminCaKey=$usersMspAdminDir/Admin@$CN-key.pem

	createCerts "Admin@$CN" $caCert $caKey $adminCaCsr $adminCaCert $adminCaKey $usersMspAdminDir "false" "NULL" "client" "usr_cert"
	adminCaKey=$usersMspAdminDir/$(getAKI $adminCaCert)"_sk"
	
	cp $tlscaCert $usersMspTlscaDir
	cp $caCert $usersMspCaDir
	cp $adminCaCert $usersMspSignDir
	mv $adminCaKey $usersMspKeyDir

	typeset mspTlscacertsDir=$mspDir"/tlscacerts"
	typeset mspCacertsDir=$mspDir"/cacerts"
	typeset mspAdmincertsDir=$mspDir"/admincerts"

	mkdir -p $mspTlscacertsDir $mspCacertsDir $mspAdmincertsDir
	cp $tlscaCert $mspTlscacertsDir
	cp $caCert $mspCacertsDir
	cp $adminCaCert $mspAdmincertsDir

	typeset mspConfig=$mspDir/config.yaml
	cp $configTemplate $mspConfig
	sed -i "s,%%cacerts,"cacerts/"$(basename $caCert),g" $mspConfig

	typeset userNO=1
	while [[ $userNO -le $userCount ]]
	do
		typeset usersDir=$userDir/User$userNO@$CN
		typeset usersTlsDir=$usersDir"/tls"
		typeset usersMspDir=$usersDir"/msp"
		typeset usersMspTlscaDir=$usersDir"/msp/tlscacerts"
		typeset usersMspSignDir=$usersDir"/msp/signcerts"
		typeset usersMspKeyDir=$usersDir"/msp/keystore"
		typeset usersMspCaDir=$usersDir"/msp/cacerts"
		typeset usersMspAdminDir=$usersDir"/msp/admincerts"

		mkdir -p $usersDir $usersTlsDir $usersMspDir $usersMspTlscaDir $usersMspSignDir $usersMspKeyDir $usersMspCaDir $usersMspCaDir $usersMspAdminDir

		# generate TLS Admin user certs
		typeset userTlscaCsr=$usersTlsDir/User$userNO@$CN-csr.pem
		typeset userTlscaCert=$usersTlsDir/User$userNO@$CN-cert.pem
		typeset userTlscaKey=$usersTlsDir/User$userNO@$CN-key.pem

		createCerts "User$userNO@$CN" $tlscaCert $tlscaKey $userTlscaCsr $userTlscaCert $userTlscaKey $usersTlsDir "false" "NULL" "NULL" "usr_cert"
		userTlscaKey=$usersTlsDir/$(getAKI $userTlscaCert)"_sk"
		
		mv $userTlscaCert $usersTlsDir/client.crt
		mv $userTlscaKey $usersTlsDir/client.key
		cp $tlscaCert $usersTlsDir/ca.crt
		
		# generate CA Admin user certs
		typeset userCaCsr=$usersMspAdminDir/User$userNO@$CN-csr.pem
		typeset userCaCert=$usersMspAdminDir/User$userNO@$CN-cert.pem
		typeset userCaKey=$usersMspAdminDir/User$userNO@$CN-key.pem

		createCerts "User$userNO@$CN" $caCert $caKey $userCaCsr $userCaCert $userCaKey $usersMspAdminDir "false" "NULL" "client" "usr_cert"
		userCaKey=$usersMspAdminDir/$(getAKI $userCaCert)"_sk"
		
		cp $tlscaCert $usersMspTlscaDir
		cp $caCert $usersMspCaDir
		cp $userCaCert $usersMspSignDir
		mv $userCaKey $usersMspKeyDir
		(( userNO+=1 ))
	done

	peerNO=0;
	while [[ $peerNO -lt $peerCount ]]
	do
		typeset peersDir=$peerDir/peer$peerNO.$CN
		typeset peerTlsDir=$peersDir"/tls"
		typeset peerMspDir=$peersDir"/msp"
		typeset peerMspTlscaDir=$peersDir"/msp/tlscacerts"
		typeset peerMspSignDir=$peersDir"/msp/signcerts"
		typeset peerMspKeyDir=$peersDir"/msp/keystore"
		typeset peerMspCaDir=$peersDir"/msp/cacerts"
		typeset peerMspAdminDir=$peersDir"/msp/admincerts"

		mkdir -p $peerDir $peerTlsDir $peerMspDir $peerMspTlscaDir $peerMspSignDir $peerMspKeyDir $peerMspCaDir $peerMspCaDir $peerMspAdminDir
		
		# generate TLS Admin peer certs
		typeset peerTlscaCsr=$peerMspTlscaDir/peer$peerNO.$CN-csr.pem
		typeset peerTlscaCert=$peerMspTlscaDir/peer$peerNO.$CN-cert.pem
		typeset peerTlscaKey=$peerMspTlscaDir/peer$peerNO.$CN-key.pem

		createCerts "peer$peerNO.$CN" $tlscaCert $tlscaKey $peerTlscaCsr $peerTlscaCert $peerTlscaKey $peerMspTlscaDir "false" "NULL" "NULL" "usr_cert"
		peerTlscaKey=$peerMspTlscaDir/$(getAKI $peerTlscaCert)"_sk"

		mv $peerTlscaCert $peerTlsDir/server.crt
		mv $peerTlscaKey $peerTlsDir/server.key
		cp $tlscaCert $peerTlsDir/ca.crt
		
		# generate CA Admin user certs
		typeset peerCaCsr=$peerMspCaDir/peer$peerNO.$CN-csr.pem
		typeset peerCaCert=$peerMspCaDir/peer$peerNO.$CN-cert.pem
		typeset peerCaKey=$peerMspCaDir/peer$peerNO.$CN-key.pem

		createCerts "peer$peerNO.$CN" $caCert $caKey $peerCaCsr $peerCaCert $peerCaKey $peerMspCaDir "false" "NULL" "peer" "usr_cert"
		peerCaKey=$peerMspCaDir/$(getAKI $peerCaCert)"_sk"

		cp $tlscaCert $peerMspTlscaDir
		cp $caCert $peerMspCaDir
		mv $peerCaCert $peerMspSignDir
		mv $peerCaKey $peerMspKeyDir
		cp $adminCaCert $peerMspAdminDir
		
		typeset peerMspConfig=$peerMspDir/config.yaml
		cp $configTemplate $peerMspConfig
		sed -i "s,%%cacerts,"cacerts/"$(basename $caCert),g" $peerMspConfig
		(( peerNO+=1 ))
	done
}

workDir=$PWD
cryptoDir=$PWD/crypto-config
ordererDir=$PWD/crypto-config/ordererOrganizations
peerDir=$PWD/crypto-config/peerOrganizations

if [[ -d $cryptoDir ]] ; then
	rm -rf $cryptoDir
fi
mkdir -p $cryptoDir $ordererDir $peerDir
generateOrdererCerts $ordererDir $rootCert $rootKey example.com
generatePeerCerts $peerDir $rootCert $rootKey org1.example.com 2 2
generatePeerCerts $peerDir $rootCert $rootKey org2.example.com 2 2
