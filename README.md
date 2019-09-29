# trafficanalysis
The repo is a dump of PCAPs and documents surrounding analysis of those PCAPs using Zeek logs via Splunk. Each PCAP has a corresponding text file that is just the same filename with .md appended to it. I've preserved these in two different directories, and the PCAPs are just for archive purposes (in case Malware-Traffic-Analysis.net is down or something). In any case, I highly recommend not using the pcaps, but instead using the mta tool to pull from Malware-Traffic-Analysis.net and automatically replay through your interface. I'm using ens160 in the snippet below, so change it to whatever your monitoring interface is.

Most of these pcaps are courtesy of the excellent Malware-Traffic-Analysis.net.

Add this to ~/.bashrc or ~/.bash_profile to add 2 new alias commands that both just get pcaps as arguments. Both use ens160 interface. You'll need to refresh your session to make sure the updated bashrc is working as intended.
```
#Replay - just a quick shortcut for churning a pcap across ens160
alias replay='sudo tcpreplay -M 5 -i ens160'
# this function creates the "mta" command which will accept pcap url from malware-traffic-analysis.net and speed (in Mbps) for a replay
# mta https://www.malware-traffic-analysis.net/2018/09/27/2018-09-27-traffic-analysis-exercise.pcap.zip 10
mta () {
link=${1}
speed=${2:-5}
file=`echo $link| sed 's/.*\///' | sed 's/\.zip$//g'`
wget -q $link ; unzip -o -P infected $file; sudo tcpreplay -M $speed -i ens160 $file
}
```

To use at 10Mbps (if no second argument, it defaults to 5);  
`mta https://www.malware-traffic-analysis.net/2018/09/27/2018-09-27-traffic-analysis-exercise.pcap.zip 10`
