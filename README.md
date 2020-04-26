# 5G_ciphered_NAS_decipher_tool
  A python tool to decipher/decrypt 5G ciphered NAS message and export plain 5G NAS into wireshark pcap file
  During my work in 5G testing and troubleshooting, I have been seeing many cases that 5G NAS message captured in wireshark are ciphered by AES,snow3G, or ZUC, and the SUCI in registration request could also be ciphered by profileA/profileB defined in 3gPP 33.501.
So I come up with this idea to write a python program to decipher the 5G NAS payload retrieved from pcap file, then write the plain NAS payload back into the pcap file. By that, we can browse and check the deciphered NAS details by wireshark very easily.
# Python dependencies of this tool:
  pyshark: https://github.com/KimiNewt/pyshark/ Python wrapper for tshark, allowing python packet parsing using wireshark dissectors
  
  pycryptodome: https://github.com/Legrandin/pycryptodome a self-contained Python package of low-level cryptographic primitives
  
  cryptography: https://github.com/pyca/cryptography a package which provides cryptographic recipes and primitives to Python developers
  
  CryptoMobile: https://github.com/mitshell/CryptoMobile python wrappers around 3G and LTE encryption and integrity protection   algorithms 


# Supported ciphering algorithm:
  a.	SUCI encryption based on profile A(curve 22519)  or profile B( EC secp256r1)
  
  b.	NAS ciphering with EEA1(snow3G)/EEA2(AES)/EEA3(ZUC)
# Current limitation:
  Support 5G AKA authentication only, no EAP-AKA’ support.
# Environment/Versions
  wireshark 3.0+ on windows 7/10.
# The basic idea of how to decipher the 5G NAS message:
  3GPP TS 33.501 Annex C defines Elliptic Curve Integrated Encryption Scheme (ECIES) to conceal the Subscription Permanent Identifier(SUPI) in registration request. The encrption of ECIES profileA or profileB is based on below diagram, so if we have the private key of home network, and retreive the Eph. public key of UE in regisration request message from pcap file,then we can compute the Eph. shared key based on the private key of home network and Eph. public key of UE. With the Eph. shared key computed, we can derive Eph. decription key to decrypt the SUCI and get the plain text based SUPI.
  Encryption of SUPI based on ECIES:
  ![Encryption based on ECIES at UE](/images/ECIES.png)
  
  Further more, after getting SUPI,if we have the secret key of UE and OP(or OPc) of network,we can retrieve the RAND/MAC/RES value from authentication request in pcap file, then compute the CK/IK based on Milenage algorithm(3GPP 35.205/35.206) on our own. With the CK/IK and below key derivation scheme defined in 3GPP 33.501, we can eventually derive the KAMF and the subsquent KNASenc key to decipher the NAS payload.
  Key derivation scheme defined by 33.501, based on which we could compute the Eph. shared key and encryption key for SUCI decryption.
  
  ![Key derivation scheme defined by 33.501](/images/key-derivation.png)
  5G AKA authentication procedure defined by 33.501, from which we could retrieve the RAND value and compute CK/IK and eventually get the encryption key of NAS to decrypt NAS payload.
  
  ![5G AKA authentication procedure defined by 33.501](/images/AKA.png)
  
  An alternative way to derive KAMF and KNASenc key is to capture the message between AUSF and SEAF, then derive the Kseaf from message, by that, we can eventually derive the KAMF & KNASenc without having to get the secret key and OP value,as usually secret key and OP are quite confidential and won't be exposed to outside user. This tool currently support deriving the encryption key based on secret key and OP only, as it's supposed to use for internal testing so it's shouldn't be a problem to get secret key and OP, it may support derive encription key based on Kseaf capture between AUSF and SEAF(AMF).
  
# Prerequisite:
  a.	Your pcap need to contain the registration request or identity response message from UEs so that the tool could retrieve the SUPI from that, the pcap need to contain authentication request message as well so that the tool could retrieve the CK/IK based on the rand value during authentication procedure.
  
  b.	Running on windows 7/10 only.
  
  c.	Wireshark 3.0 or above installed on the computer on which this tool is running, as tshark of wireshark is needed to read the pcap file. Old wireshark(lower than 3.0) may not decode new 5G nas message well.
  
 
