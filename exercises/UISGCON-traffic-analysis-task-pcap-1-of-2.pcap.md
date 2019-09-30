## https://www.malware-traffic-analysis.net/2018/UISGCON/index.html
pass: infected

LAN SEGMENT PROPERTIES:

IP range:  172.16.1.0/24 (172.16.1.0 through 172.16.1.255)
Gateway IP:  172.16.1.1
Broadcast IP:  172.16.1.255
Domain Controller (DC):  Maricheika-DC at 172.16.1.3
Domain:  maricheika.net
TASKS I SUGGESTED:

State the time and date of this infection.
The time, as usual, won't be accurate due to how I'm replaying data. However as an exercise, this is where I would run it down.

Check the log types first;  
```
index=zeek | stats count by sourcetype
```

If I have no direction then I find it useful to sometimes look at the notice.log before anything else, just to see what sticks out.  
```
index=zeek sourcetype="bro:notice:json"
```

One of the notices refers to a host with a self signed cert. Investigating the UID reveals that it was an established connection (from conn_state_meaning in conn.log with usereneventheg.ru (seen in ssl.log as the server_name that is associated with the cert. I run intelstack along with several intel sources, and one of those (sslbl.abuse.ch) let me know that the hash has been seen on their ssl abuse list.   
```
index=zeek uid=CX7uJh27nqdmMgqUa6
```
___
Determine the IP address of the infected Windows client.    
**172.16.1.125**  
```
index=zeek uid=CX7uJh27nqdmMgqUa6 | table id.orig_h
```
___

Determine the host name of the infected Windows client.  
Determine the MAC address of the infected Windows client.  
**Anatoliy-PC	b8:97:fa:74:de:c0**  
```
index=zeek  172.16.1.125 sourcetype="bro:dhcp:json" 
|  table host_name mac 
|  dedup host_name
```
___
Determine the Windows user account name used on the infected Windows client.  
**anatoliy.demchuk/MARICHEIKA.NET**
```
index=zeek 172.16.1.125 sourcetype="bro:kerberos:json" 
| dedup client 
| table client
```
___
Determine the SHA256 hash of the Word document downloaded by the victim.
I don't naturally remember mimetypes all that well so I usually use `index=zeek 172.16.1.125 | stats count by mime_type` to list them. We see that there was only one word doc so we can easily pivot to that;  
```
index=zeek 172.16.1.125 mime_type="application/msword" 
| table sha256 filename
```
___
Determine the type of malware used in the initial infection.  
**Hancitor**
https://www.virustotal.com/gui/file/e2b0c9f57dcf08c0e14456f5cb54d8e50714c8e7a3a88cf818896dc8ba1dba51/detection
*If this is a repetitive action, I recommend setting up a "workflow action" in Splunk to quickly pivot from Splunk to Virustotal.*
___
Determine the public IP address of the infected Windows client.  
This information is unavailable in Bro data as it doesn't show up in protocol specific metadata. 
