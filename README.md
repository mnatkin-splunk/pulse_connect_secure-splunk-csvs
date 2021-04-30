# pulse_connect_secure-splunk-csvs
 Pulse Connect Secure RCE, Webkit, and related vulnerabilities

IOCs (IP addresses, hashes of web shell .aspx files, names of .aspx files, user-agents) used in exploiting CVE-2021-22893, courtesy FireEye

This repository is a companion to the article published at https://www.splunk.com/en_us/blog/security/monitoring-pulse-connect-secure-with-splunk-cisa-emergency-directive-21-03.html


For a simple Splunk UF scanning scripts to harvest versions of Pulse Secure Connect appliances via web interface, head over to https://github.com/stressboi/TA-pcsverchecker   #thanksbrodsky


FireEye Blog
https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html

Pulse Links:
https://blog.pulsesecure.net/pulse-connect-secure-security-update/
https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44784/
https://kb.pulsesecure.net/articles/Pulse_Secure_Article/TSB44767 
https://kb.pulsesecure.net/articles/Pulse_Secure_Article/KB44755 (Linked from FireEye blog)
Prior advisory (unpatched vulns still being exploited) https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101/ 
Countermeasures:
https://github.com/fireeye/pulsesecure_exploitation_countermeasures

News:
https://news.trust.org/item/20210420125405-ukie9/

CISA Advisory:
https://us-cert.cisa.gov/ncas/current-activity/2021/04/20/cisa-releases-alert-exploitation-pulse-connect-secure 
https://us-cert.cisa.gov/ncas/alerts/aa-21-110a 
Prior advisory (unpatched vulns providing beachhead): https://us-cert.cisa.gov/ncas/alerts/aa20-010a 

DHS Emergency Directive 21-03 
https://cyber.dhs.gov/ed/21-03/ 


20210422 UPDATE
Added procdump and IP IOC details pursuant to AR21-112A

20210430 UPDATE
Added IOC details pursuant to updates posted to AR21-110A

Use these as lookup tables in Splunk for simple IOC matching. Note: if you want to use these with ES, you need to use the versions in the EnterpriseSecurity directory. See blog post here for guidance: https://www.splunk.com/en_us/blog/security/smoothing-the-bumps-of-onboarding-threat-indicators-into-splunk-enterprise-security.html

If you wish to add more IOCs to this repo, please send a PR!

30APR2021