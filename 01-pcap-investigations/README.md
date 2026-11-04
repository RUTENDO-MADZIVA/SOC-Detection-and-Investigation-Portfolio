# PCAP Investigations

Packet-capture investigations using Wireshark and public exercises (for example from malware-traffic-analysis.net).

**Safety:** open only the `.pcap` file, never any malware sample supplied with an exercise. Capture files are excluded from this repo by `.gitignore`.

Workflow:
1. Statistics > Conversations to find unusual hosts
2. Identify the victim host (DHCP, NBNS, Kerberos)
3. Look at DNS, HTTP and TLS server names
4. Build a timeline and collect indicators
5. Check indicators on VirusTotal
6. Write the report using `../report-template.md`

| Report | Source exercise | Verdict |
|--------|-----------------|---------|
| [add after completing] | | |
