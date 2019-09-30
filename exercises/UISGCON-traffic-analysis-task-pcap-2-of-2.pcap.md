https://www.malware-traffic-analysis.net/2018/UISGCON/index.html
pass: infected

LAN SEGMENT PROPERTIES:

IP range:  10.1.75.0/24 (10.1.75.0 through 10.1.75.255)
Gateway IP:  10.1.75.1
Broadcast IP:  10.1.75.255
Domain Controller (DC):  PixelShine-DC at 10.1.75.4
Domain:  pixelshine.net

TASKS I SUGGESTED:

State the time and date of this infection.  
**Inaccurate based on replay method**
___
Determine the IP address of the infected Windows client.
**10.1.75.167**
notice.log shows 4 self signed certs. Lets look at the the total amount of events with those UIDs. We'll sum it all up in a subsearch;  
```
index=zeek 
    [ search index=zeek sourcetype="bro:notice:json" 
    | table uid] 
```
Its easy to make assumptions on who is infected with these results, but this is really only because the scope is so narrow at this point. With additional logging such as intelstack however, we can see right now that both the DC and 10.1.75.167 have seen abuse.ch x509 related IOC hits. In fact, of the thousands of IOCs that I currently have loaded, I had 41 hits from this pcap along (cert hash, url, file hash, domain, and ip address). Outside of Bro, this pcap generated 338 IDS events. (Potentially Bad Traffic, A Network Trojan was detected, etc). Its worth mentioning the value of decent intel, even opensource, because with it the answer to this question was immediate (hint, its dridex. https://sslbl.abuse.ch/ssl-certificates/sha1/4e063cd8a403641d037929a52ebafa47d47f8afa/)  
___
Determine the host name of the infected Windows client.  
Determine the MAC address of the infected Windows client.  
**00:1f:cf:8b:32:9e	Rigsby-Win-PC**
```
index=zeek 10.1.75.167 sourcetype="bro:dhcp:json" 
| table mac host_name
```
___
Determine the Windows user account name used on the infected Windows client.  
**judson.rigsby/PIXELSHINE.NET**
```
index=zeek 10.1.75.167 sourcetype="bro:kerberos:json" 
| dedup client 
| table client
```
___
Determine the SHA256 hash of the Word document downloaded by the victim.  
**1112203340b2d66f15b09046af6e776af6604343c1e733fe419fdf86f851caa3	FILE-88654515940798.doc**
```
index=zeek 10.1.75.167 mime_type="application/msword"
| table sha256 filename
```
___
Determine the SHA256 hash of the first malware binary sent to the infected Windows client.
**0d7a4650cdc13d9217edb05f5b5c2c5528f8984dbbe3fbc85f4a48ae51846cc3**  
and there is more than one;  
```
index=zeek 10.1.75.167 sourcetype="bro:files:json" mime_type=application/x-dosexec 
| table _time filename mime_type sha256
```
___
Determine the time the Domain Controller (DC) at 10.1.75.4 became infected.
**2019-09-30 02:18:46	\WINDOWS\9b4ui3u2fj1o666n8jy2ribbbaj4qpqeyotv22ksrtadl3p6vzn4fjgek2ljjqca.exe	application/x-dosexec	28c33a9676f04274b2868c1a2c092503a57d38833f0f8b964d55458623b82b6e**  
```
index=zeek 10.1.75.4 sourcetype="bro:files:json"
| table _time filename mime_type sha256
```
___
Determine the SHA256 hash of the second malware binary sent to the infected Windows client (same file retrieved as radiance.png and table.png).
**0dc9d82d2f9d9ae27a1cb6d64ec7ab73bcee16d327027dba1273cbcc33849f9f**  
The question gives away too much of the fun. This executable is disguised as /radiance.png   
```
index=zeek 10.1.75.167 sourcetype="bro:files:json" mime_type=application/x-dosexec 
| table _time filename mime_type sha256
```
___
What are the two file hashes for executables you can retrieve from the SMB traffic using Wireshark?
**28c33a9676f04274b2868c1a2c092503a57d38833f0f8b964d55458623b82b6e 	cf99990bee6c378cbf56239b3cc88276eec348d82740f84e9d5c343751f82560**  
This can be done using the "source" field or the "extracted" field since the file framework also extracts executables from SMB traffic.

```
index=zeek 10.1.75.167 sourcetype="bro:files:json" mime_type=application/x-dosexec (source=*SMB* OR extracted=*SMB-*)
| table _time filename mime_type sha256
```
If you like validation, you can peruse other filetypes with the same conn_uids;  
```
index=zeek [ search index=zeek sourcetype="bro:files:json" mime_type=application/x-dosexec (source=*SMB* OR extracted=*SMB-*) 
    | rename conn_uids as uid 
    | table uid] 
|  stats count by sourcetype
```
___
Determine the two families of malware the Windows client was infected with.
**Trickbot (2 exes), emotet, unknown downloader as well**
```
index=zeek 10.1.75.167 sourcetype="bro:files:json" 
| table _time filename mime_type sha256
```
___
Determine the one family of malware the DC was infected with.
**trickbot**  
```
index=zeek 10.1.75.4 sourcetype="bro:files:json" attachment_type="application/x-dosexec" 
|  dedup sha256
```
___
Determine the public IP address of the infected Windows client.
**Not available in the protocol data**
