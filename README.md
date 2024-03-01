# .Net-Deserialization-Cheat-Sheet
A cheat sheet for pentesters and researchers about deserialization vulnerabilities in various .Net serialization libraries.

Please, use **#.netdeser** hash tag for tweets.

##  Table of content
- [.Net Serialization]
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
##### Exploiting Deserialization Vulnerabilities in .Net
by [@matthias_kaiser](https://twitter.com/matthias_kaiser)

- [Video](https://www.youtube.com/watch?v=VviY3O-euVQ)

##### Serial Killer: Silently Pwning Your .Net Endpoints
by [@pwntester](https://twitter.com/pwntester)

- [Slides](https://speakerdeck.com/pwntester/dot-net-serialization-detecting-and-defending-vulnerable-endpoints)
- [White Paper](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [YsoSerial.Net](https://github.com/pwntester/ysoserial.net)

##### payload-generators
- [ysoserial.net | A proof-of-concept tool for generating payloads that exploit unsafe .NET object deserialization.](https://github.com/pwntester/ysoserial.net)
- [ysoserial.net v2 Branch](https://github.com/pwntester/ysoserial.net/tree/v2)
- [Exploiting Deserialisation in ASP.NET via ViewState by Soroush Dalili (@irsdl) Blog](https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/)
- [Exploiting .NET Managed DCOM by James Forshaw, Project Zero](https://googleprojectzero.blogspot.com/2017/04/exploiting-net-managed-dcom.html)
- [heyserial by @mandiant](https://github.com/mandiant/heyserial/tree/main/payloads/dotnet)

##### Links
	
-[Serialization and Deserialization in C#](https://www.c-sharpcorner.com/article/serialization-and-deserialization-in-c-sharp/)
 
-[hunting-deserialization-exploits](https://www.mandiant.com/resources/blog/hunting-deserialization-exploits)

-[White paper / Are you my Type?](https://github.com/TraceSrc/.Net-Sterilized--Deserialization-Exploitation/blob/master/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)

-[A Spirited Peek into ViewState, Part I](https://deadliestwebattacks.com/archive/2011-05-13-a-spirited-peek-into-viewstate-part-i)

-[Deep Dive into .NET ViewState deserialization and its exploitation](https://swapneildash.medium.com/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817)



-[Use of Deserialisation in.NET Framework Methods and Classes by Soroush Dalili (@irsdl)](https://research.nccgroup.com/wp-content/uploads/2020/07/whitepaper-new.pdf)


-[ASP.NET ViewState Generator](https://github.com/0xacb/viewgen)

-[Yet Another .NET deserialization](https://medium.com/@frycos/yet-another-net-deserialization-35f6ce048df7)



-[Shmoocon2022_CleanUpOnTheSerialAisle_AlyssaRahman.pdf](https://github.com/mandiant/heyserial/blob/main/Shmoocon2022_CleanUpOnTheSerialAisle_AlyssaRahman.pdf)

-[CVE-2019-18935: Remote Code Execution via Insecure Deserialization in Telerik UI](https://bishopfox.com/blog/cve-2019-18935-remote-code-execution-in-telerik-ui)

-[Microsoft Exchange Server ChainedSerializationBinder Remote Code Execution | CVE-2021-42321, CVE-2022-23277](https://packetstormsecurity.com/files/168131/Microsoft-Exchange-Server-ChainedSerializationBinder-Remote-Code-Execution.html)

-[Unsafe Deserialization in .NET Vulnerable Example](https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization__net.html)

-[JSON.NET Deserialization Explaination](https://exploit-notes.hdks.org/exploit/web/security-risk/json-net-deserialization/)

-[Basic .Net deserialization (ObjectDataProvider gadget, ExpandedWrapper, and Json.Net)](https://book.hacktricks.xyz/pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net)

-[Note nhanh về BinaryFormatter binder và CVE-2022–23277](https://testbnull.medium.com/note-nhanh-v%E1%BB%81-binaryformatter-binder-v%C3%A0-cve-2022-23277-6510d469604c)

-[Real World .NET Examples Of Deserialization Vulnerabilities](https://www.c-sharpcorner.com/article/real-world-net-examples-of-deserialization-vulnerabilities/)

-[freddy-deserialization-bug-finder "Burp Extention"](https://github.com/portswigger/freddy-deserialization-bug-finder)

-[Microsoft Security Advisory CVE-2023-21808: .NET Remote Code Execution Vulnerability](https://github.com/dotnet/announcements/issues/247)

-[How I Get Pre-Auth Remote Code Execution (CVE-2021–42237) on One of the Vendors.](https://caesarevan23.medium.com/how-i-get-pre-auth-remote-code-execution-cve-2021-42237-on-one-of-the-vendors-f62e35cb90de)

-[Analysis and explotation of 2019-10068, a Remote Command Execution in Kentico CMS <= 12.04](https://dreadlocked.github.io/2019/10/25/kentico-cms-rce/)
 
-[CVE-2021-34992 Deserialization of Untrusted Data "Orckestra C1 CMS"](https://www.zerodayinitiative.com/advisories/ZDI-21-1304/)

-[]()
 
-[insecure-deserialisation-net-poc](https://github.com/omerlh/insecure-deserialisation-net-poc)

-[Insecure Deserialization with JSON .NET](https://medium.com/r3d-buck3t/insecure-deserialization-with-json-net-c70139af011a)
 
 
 
 
 ```
CVE-2021-26857 is an insecure deserialization vulnerability in the Unified Messaging service.
Insecure deserialization is where untrusted user-controllable data is deserialized by a program.
Exploiting this vulnerability gave HAFNIUM the ability to run code as SYSTEM on the Exchange server. 
This requires administrator permission or another vulnerability to exploit.
```


