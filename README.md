# .Net-Deserialization-Cheat-Sheet
A cheat sheet for pentesters and researchers about deserialization vulnerabilities in various .Net serialization libraries.

Please, use **#.netdeser** hash tag for tweets.

##  Table of content
- [.Net Serialization](#.Net-Serialization)
	- [Overview](#overview)
	- [Main talks & presentations & docs](#main-talks--presentations--docs)
	- [Payload generators](#payload-generators)
	- [Exploits](#exploits)
	- [Detect](#detect)
	- [Protection](#protection)

## .Net Serialization

### Overview
- [.Net Deserialization Security FAQ](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)
- [From Foxgloves Security ]

### Main talks & presentations & docs
##### Exploiting Deserialization Vulnerabilities in .Net
by [@pwntester](https://twitter.com/pwntester)

- [Video](https://www.youtube.com/watch?v=eDfGpu3iE4Q)

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

## .Net Serialization BinaryFormatter

#### CVE-2020-25258
- [CVE Details](https://nvd.nist.gov/vuln/detail/CVE-2020-25258)
- [Hyland OnBase 19.x and below - Insecure Deserialization](https://seclists.org/fulldisclosure/2020/Sep/22)

#### CVE-2021-29508
- [CVE Details](https://nvd.nist.gov/vuln/detail/CVE-2021-29508)
- [Do not use Wire - Insecure deserialization](https://github.com/asynkron/Wire/security/advisories/GHSA-hpw7-3vq3-mmv6)
- [CA2300: Do not use insecure deserializer BinaryFormatter](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2300?view=vs-2019)

#### CVE-2023-3513
- [CVE Details](https://nvd.nist.gov/vuln/detail/CVE-2023-3513)
- [RazerCentralService unsafe deserialization Escalation of Privilege Vulnerability](https://starlabs.sg/advisories/23/23-3513/)
- [Windows Online Certificate Status Protocol (OCSP) SnapIn Remote Code Execution Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35313)

#### CVE-2021-27076
- [CVE Details](https://nvd.nist.gov/vuln/detail/CVE-2021-27076)
- [A REPLAY-STYLE DESERIALIZATION ATTACK AGAINST SHAREPOINT](https://www.zerodayinitiative.com/blog/2021/3/17/cve-2021-27076-a-replay-style-deserialization-attack-against-sharepoint)
- [Microsoft SharePoint Server Remote Code Execution Vulnerability](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-27076)

##### Vulnerable code For .Net Serialization BinaryFormatter
```
    class Program
    {
        static void Main(string[] args)
        {
            // Serialize
            var ship = new Ship();
            var formatter = new BinaryFormatter();
            using (var stream = new MemoryStream())
            {
                formatter.Serialize(stream, ship);
                // The serialized data is now in the 'stream' variable
            }

            // Deserialize
            using (var stream = new MemoryStream(/* Load your serialized data here */))
            {
                var deserializedShip = (Ship)formatter.Deserialize(stream);
                // Use the deserialized object
            }
        }
    }

```
##### Secure code For .Net Serialization BinaryFormatter
```
    class Program
    {
        static void Main(string[] args)
        {
            // Serialize
            var ship = new Ship();
            var formatter = new BinaryFormatter();

            try
            {
                using (var stream = new MemoryStream())
                {
                    formatter.Serialize(stream, ship);
                    // The serialized data is now in the 'stream' variable
                }
            }
            catch (SerializationException ex)
            {
                Console.WriteLine($"Serialization error: {ex.Message}");
                // Handle the exception appropriately (e.g., log, notify, etc.)
            }

            // Deserialize
            try
            {
                using (var stream = new MemoryStream(/* Load your serialized data here */))
                {
                    var deserializedShip = (Ship)formatter.Deserialize(stream);
                    // Use the deserialized object
                }
            }
            catch (SerializationException ex)
            {
                Console.WriteLine($"Deserialization error: {ex.Message}");
                // Handle the exception appropriately (e.g., log, notify, etc.)
            }
        }
    }

```

## Other 

- [SoapFormatter](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.soap.soapformatter)
- [LosFormatter](https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.losformatter)
- [NetDataContractSerializer](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.serialization.netdatacontractserializer)
- [ObjectStateFormatter](https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.objectstateformatter)

## .Net Serialization LosFormatter

#### CVE-2020-1147
- [CVE Details](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-1147)
- [Microsoft SharePoint Remote Code Execution Vulnerability](https://threatprotect.qualys.com/2020/07/24/microsoft-sharepoint-remote-code-execution-vulnerability-cve-2020-1147/)
- [SharePoint DataSet / DataTable Deserialization](http://packetstormsecurity.com/files/158694/SharePoint-DataSet-DataTable-Deserialization.html)
- [Microsoft SharePoint Server 2019 Remote Code Execution](http://packetstormsecurity.com/files/158876/Microsoft-SharePoint-Server-2019-Remote-Code-Execution.html)

#### CVE-2020-0618
- [CVE Details](https://nvd.nist.gov/vuln/detail/cve-2020-0618)
- [RCE in SQL Server Reporting Services (SSRS)](https://www.mdsec.co.uk/2020/02/cve-2020-0618-rce-in-sql-server-reporting-services-ssrs/)
- [Exploit](http://packetstormsecurity.com/files/156707/SQL-Server-Reporting-Services-SSRS-ViewState-Deserialization.html)

## .Net Serialization NetDataContractSerializer

#### CVE-2021-42237
- [CVE Details](https://nvd.nist.gov/vuln/detail/CVE-2021-42237)
- [Sitecore Experience Platform Pre-Auth RCE](https://www.assetnote.io/resources/research/sitecore-experience-platform-pre-auth-rce-cve-2021-42237)
- [Pre-Auth Remote Code Execution Medium Blog)](https://caesarevan23.medium.com/how-i-get-pre-auth-remote-code-execution-cve-2021-42237-on-one-of-the-vendors-f62e35cb90de)

## .Net Serialization ObjectStateFormatter

#### CVE-2017-9822
- [DotNetNuke Cookie Deserialization Remote Code Execution (RCE)](https://github.com/murataydemir/CVE-2017-9822)
- [How to exploit the DotNetNuke Cookie Deserialization](https://pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization)
- [Exploit](http://packetstormsecurity.com/files/157080/DotNetNuke-Cookie-Deserialization-Remote-Code-Execution.html)
- [HackerOne Report](https://hackerone.com/reports/876708)

#### CVE-2018-15811
- [CVE Details](https://www.cvedetails.com/cve/CVE-2018-15811/)
- [How to exploit the DotNetNuke Cookie Deserialization](https://pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization)
- [Exploit](http://packetstormsecurity.com/files/157080/DotNetNuke-Cookie-Deserialization-Remote-Code-Execution.html)

#### CVE-2018-15812
- [CVE Details](https://www.cvedetails.com/cve/CVE-2018-15812/)
- [How to exploit the DotNetNuke Cookie Deserialization](https://pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization)
- [Exploit](http://packetstormsecurity.com/files/157080/DotNetNuke-Cookie-Deserialization-Remote-Code-Execution.html)

#### CVE-2018-18325
- [CVE Details](https://www.cvedetails.com/cve/CVE-2018-18325)
- [How to exploit the DotNetNuke Cookie Deserialization](https://pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization)
- [Exploit](http://packetstormsecurity.com/files/157080/DotNetNuke-Cookie-Deserialization-Remote-Code-Execution.html)

#### CVE-2018-18326
- [CVE Details](https://www.cvedetails.com/cve/CVE-2018-18326)
- [How to exploit the DotNetNuke Cookie Deserialization](https://pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization)
- [Exploit](http://packetstormsecurity.com/files/157080/DotNetNuke-Cookie-Deserialization-Remote-Code-Execution.html)


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

-[BlueHat v17 || Dangerous Contents - Securing .Net Deserialization](https://www.youtube.com/watch?v=oxlD8VWWHE8)
 
 
 ```
CVE-2021-26857 is an insecure deserialization vulnerability in the Unified Messaging service.
Insecure deserialization is where untrusted user-controllable data is deserialized by a program.
Exploiting this vulnerability gave HAFNIUM the ability to run code as SYSTEM on the Exchange server. 
This requires administrator permission or another vulnerability to exploit.
```


