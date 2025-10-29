<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.94SVN scan initiated Wed Oct 29 13:46:38 2025 as: nmap -sV -&#45;script http-vuln-*,ssl-* -p 80,443 -oX scan_web.xm 192.168.178.36 -->
<nmaprun scanner="nmap" args="nmap -sV -&#45;script http-vuln-*,ssl-* -p 80,443 -oX scan_web.xm 192.168.178.36" start="1761741998" startstr="Wed Oct 29 13:46:38 2025" version="7.94SVN" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="2" services="80,443"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.178.36" addrtype="ipv4"/>
<address addr="D8:BB:C1:FA:37:15" addrtype="mac" vendor="Micro-Star Intl"/>
<hostnames>
</hostnames>
</hosthint>
<host starttime="1761741998" endtime="1761741998"><status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.178.36" addrtype="ipv4"/>
<address addr="D8:BB:C1:FA:37:15" addrtype="mac" vendor="Micro-Star Intl"/>
<hostnames>
<hostname name="MSI-Comunicando.fritz.box" type="PTR"/>
</hostnames>
<ports><port protocol="tcp" portid="80"><state state="closed" reason="reset" reason_ttl="128"/><service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="443"><state state="closed" reason="reset" reason_ttl="128"/><service name="https" method="table" conf="3"/></port>
</ports>
<times srtt="274" rttvar="2860" to="100000"/>
</host>
<runstats><finished time="1761741998" timestr="Wed Oct 29 13:46:38 2025" summary="Nmap done at Wed Oct 29 13:46:38 2025; 1 IP address (1 host up) scanned in 0.51 seconds" elapsed="0.51" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
