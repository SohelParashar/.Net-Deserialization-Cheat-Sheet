# .Net-Deserialization-Cheat-Sheet
A cheat sheet for pentesters and researchers about deserialization vulnerabilities in various .Net serialization libraries.

Please, use **#.netdeser** hash tag for tweets.

##  Table of content
- [.Net Serialization (binary)]
	- [Overview](#overview)
	- [Main talks & presentations & docs](#main-talks--presentations--docs)
	- [Payload generators](#payload-generators)
	- [Exploits](#exploits)
	- [Detect](#detect)
	- [Protection](#protection)

## .Net Serialization (binary)

### Overview
- [.Net Deserialization Security FAQ]
- [From Foxgloves Security ]

### Main talks & presentations & docs
##### Marshalling Pickles
by [@frohoff](https://twitter.com/frohoff) & [@gebl](https://twitter.com/gebl)

- [Video](https://www.youtube.com/watch?v=KSA7vUkXGSg)
- [Slides](https://www.slideshare.net/frohoff1/appseccali-2015-marshalling-pickles)
- [Other stuff](https://frohoff.github.io/appseccali-marshalling-pickles/ )

##### Exploiting Deserialization Vulnerabilities in .Net
by [@matthias_kaiser](https://twitter.com/matthias_kaiser)

- [Video](https://www.youtube.com/watch?v=VviY3O-euVQ)

##### Serial Killer: Silently Pwning Your .Net Endpoints
by [@pwntester](https://twitter.com/pwntester)

- [Slides](https://speakerdeck.com/pwntester/dot-net-serialization-detecting-and-defending-vulnerable-endpoints)
- [White Paper](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [YsoSerial.Net](https://github.com/pwntester/ysoserial.net)

##### payload-generators

##### Links
	-[Serialization and Deserialization in C#](https://www.c-sharpcorner.com/article/serialization-and-deserialization-in-c-sharp/)
 
	-[hunting-deserialization-exploits](https://www.mandiant.com/resources/blog/hunting-deserialization-exploits)

	-[White paper / Are you my Type?](https://github.com/TraceSrc/.Net-Sterilized--Deserialization-Exploitation/blob/master/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)

	-[A Spirited Peek into ViewState, Part I](https://deadliestwebattacks.com/archive/2011-05-13-a-spirited-peek-into-viewstate-part-i)

	-[Deep Dive into .NET ViewState deserialization and its exploitation](https://swapneildash.medium.com/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817)

	-[Exploiting Deserialisation in ASP.NET via ViewState by Soroush Dalili (@irsdl) Blog](https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/)

	-[Use of Deserialisation in.NET Framework Methods and Classes by Soroush Dalili (@irsdl)](https://research.nccgroup.com/wp-content/uploads/2020/07/whitepaper-new.pdf)

	-[Friday the 13th JSON Attacks white paper by Alvaro Muñoz & Oleksandr Mirosh](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)

	-[Exploiting .NET Managed DCOM by James Forshaw, Project Zero](https://googleprojectzero.blogspot.com/2017/04/exploiting-net-managed-dcom.html)

	-[ASP.NET ViewState Generator](https://github.com/0xacb/viewgen)

	-[ysoserial.net | A proof-of-concept tool for generating payloads that exploit unsafe .NET object deserialization.](https://github.com/pwntester/ysoserial.net)

	-[ysoserial.net v2 Branch](https://github.com/pwntester/ysoserial.net/tree/v2)

	-[Yet Another .NET deserialization](https://medium.com/@frycos/yet-another-net-deserialization-35f6ce048df7)

	-[heyserial by @mandiant](https://github.com/mandiant/heyserial/tree/main/payloads/dotnet)

	-[Shmoocon2022_CleanUpOnTheSerialAisle_AlyssaRahman.pdf](https://github.com/mandiant/heyserial/blob/main/Shmoocon2022_CleanUpOnTheSerialAisle_AlyssaRahman.pdf)

	-[CVE-2019-18935: Remote Code Execution via Insecure Deserialization in Telerik UI](https://bishopfox.com/blog/cve-2019-18935-remote-code-execution-in-telerik-ui)

	-[Microsoft Exchange Server ChainedSerializationBinder Remote Code Execution | CVE-2021-42321, CVE-2022-23277](https://packetstormsecurity.com/files/168131/Microsoft-Exchange-Server-ChainedSerializationBinder-Remote-Code-Execution.html)

	-[Unsafe Deserialization in .NET Vulnerable Example](https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization__net.html)

	-[JSON.NET Deserialization Explaination](https://exploit-notes.hdks.org/exploit/web/security-risk/json-net-deserialization/)

	-[Basic .Net deserialization (ObjectDataProvider gadget, ExpandedWrapper, and Json.Net)](https://book.hacktricks.xyz/pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net)

	-[Note nhanh về BinaryFormatter binder và CVE-2022–23277](https://testbnull.medium.com/note-nhanh-v%E1%BB%81-binaryformatter-binder-v%C3%A0-cve-2022-23277-6510d469604c)

	-[Real World .NET Examples Of Deserialization Vulnerabilities](https://www.c-sharpcorner.com/article/real-world-net-examples-of-deserialization-vulnerabilities/)

	-[freddy-deserialization-bug-finder "Burp Extention"](https://github.com/portswigger/freddy-deserialization-bug-finder)

 

 
 
 
	-[insecure-deserialisation-net-poc](https://github.com/omerlh/insecure-deserialisation-net-poc)

	-[Insecure Deserialization with JSON .NET](https://medium.com/r3d-buck3t/insecure-deserialization-with-json-net-c70139af011a)
 
 
 
 
 
