# 5G_ciphered_NAS_decipher_tool
A python tool to decipher/decrypt 5G ciphered NAS message and export plain 5G NAS into wireshark pcap file
During my work in 5G testing and troubleshooting, there always comes some case that 5G NAS message captured in wireshark is ciphered by AES,snow3G, or ZUC, and the SUCI could also be ciphered profileA/profileB defined by 3gPP 33.501.
So I come up with this idea to write a python program to decipher the 5G NAS payload retrieved from pcap file, then write the plain NAS payload back into the pcap file. By that, we can browse and check the NAS details by wireshark very easily.
