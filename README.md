# 5G_ciphered_NAS_decipher_tool
  A python tool to decipher/decrypt 5G ciphered NAS message and export plain 5G NAS into wireshark pcap file
  During my work in 5G testing and troubleshooting, I have been seeing many cases that 5G NAS message captured in wireshark are ciphered by AES,snow3G, or ZUC, and the SUCI in registration request could also be ciphered by profileA/profileB defined in 3gPP 33.501.
So I come up with this idea to write a python program to decipher the 5G NAS payload retrieved from pcap file, then write the plain NAS payload back into the pcap file. By that, we can browse and check the deciphered NAS details by wireshark very easily.
Python dependencies of this tool:
  pyshark: https://github.com/KimiNewt/pyshark/ Python wrapper for tshark, allowing python packet parsing using wireshark dissectors
  pycryptodome: https://github.com/Legrandin/pycryptodome a self-contained Python package of low-level cryptographic primitives
  cryptography: https://github.com/pyca/cryptography a package which provides cryptographic recipes and primitives to Python developers
  CryptoMobile: https://github.com/mitshell/CryptoMobile python wrappers around 3G and LTE encryption and integrity protection   algorithms 


Supported ciphering algorithm:
  a.	SUCI encryption based on profile A(curve 22519)  or profile B( EC secp256r1)
  b.	NAS ciphering with EEA1(snow3G)/EEA2(AES)/EEA3(ZUC)
Current limitation:
      Support 5G AKA authentication only, no EAP-AKA’ support.
Environment/Versions
  wireshark 3.0+ on windows 7/10.

Prerequisite:
  a.	Your pcap need to contain the registration request or identity response message from UEs so that the tool could retrieve the SUPI from that, the pcap need to contain authentication request message as well so that the tool could retrieve the CK/IK based on the rand value during authentication procedure.
  b.	Running on windows 7/10 only.
  c.	Wireshark 3.0 or above installed on the computer on which this tool is running, as tshark of wireshark is needed to read the pcap file. Old wireshark(lower than 3.0) may not decode new 5G nas message well.
  
