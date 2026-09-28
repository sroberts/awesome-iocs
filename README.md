# Awesome IOCs [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

Forensic artifacts, such as file hashes, domains, IP addresses and detection signatures, that identify malicious activity on a system or network.

## Contents

- [IOCs](#iocs)
  - [Indicators](#indicators)
  - [Snort Signatures](#snort-signatures)
  - [YARA Signatures](#yara-signatures)
- [Tools](#tools)
  - [IOC Tools](#ioc-tools)
  - [IOC Formats](#ioc-formats)

## IOCs

### Indicators

- [0x27/linux.mirai](https://github.com/0x27/linux.mirai) - Leaked Linux.Mirai source code for research and IOC development.
- [CyberBriefing IOC API](https://cyberbriefing.info) - Vendor-operated REST API aggregating active IOCs from public feeds (AlienVault OTX, Abuse.ch URLhaus, ThreatFox, CISA KEV, Tor exit nodes, OpenPhish); free tier requires an API key.
- [Extuno Malicious Package Database](https://extuno.com/malicious-db) - Vendor-operated database of malicious browser extensions and packages across 12 ecosystems (Chrome, Firefox, VS Code, npm, PyPI, WordPress and others), aggregated from OSV, OpenSSF and vendor feeds, with a free web lookup and JSON endpoint.
- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) - YARA rules and IOCs used by the THOR and LOKI scanners.
- [PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information](https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information) - Indicators from Unit 42 Public Reports.
- [ThreatCluster Public IOC Feed](https://threatcluster.io/feeds) - Vendor-operated feed of indicators extracted from clustered public reporting, available as TXT, CSV and JSON.
- [aptnotes/data](https://github.com/aptnotes/data) - APTnotes data.
- [botherder/targetedthreats](https://github.com/botherder/targetedthreats) - Collection of IOCs related to targeting of civil society.
- [circl/osint-feed](https://www.circl.lu/doc/misp/feed-osint/) - Open Source Intelligence for MISP.
- [citizenlab/malware-indicators](https://github.com/citizenlab/malware-indicators) - Citizen Lab Malware Reports.
- [cystack/stealer-fingerprints](https://github.com/cystack/stealer-fingerprints) - Catalog of infostealer log fingerprints (banner strings, field signatures, YARA rules) for 30+ families including RedLine, Vidar, Lumma and StealC.
- [eset/malware-ioc](https://github.com/eset/malware-ioc) - Indicators of compromise from ESET investigations.
- [hvs-consulting/ioc_signatures](https://github.com/hvs-consulting/ioc_signatures) - HvS-Consulting incident response IOCs and YARA rules, organized by threat actor or campaign.
- [jasonmiacono/IOCs](https://github.com/jasonmiacono/IOCs) - Indicators of compromise for threat intelligence.
- [nshc-threatrecon/IoC-List](https://github.com/nshc-threatrecon/IoC-List) - IOCs from the NSHC ThreatRecon team.
- [thirdeyeintelligence/IOCs-in-CSV-format](https://github.com/thirdeyeintelligence/IOCs-in-CSV-format) - IOCs in CSV format for APT, cybercrime and malware activity found during hunting and research.
- [trilwu/apttrail](https://github.com/trilwu/apttrail) - APT indicators that carry the actor they belong to, its MITRE ATT&CK group ID, when they first appeared and the report that published them.
- [volexity/threat-intel](https://github.com/volexity/threat-intel) - Indicators from Volexity public threat intelligence blog posts, organized by year and post.

### Snort Signatures

- [Snort Downloads](https://www.snort.org/downloads) - Signatures for the Snort (and Suricata) intrusion detection system.
- [kingtuna/Signatures](https://github.com/kingtuna/Signatures) - A mixture of Snort and Suricata signatures.

### YARA Signatures

- [InQuest/yara-rules](https://github.com/InQuest/yara-rules) - YARA rules shared by InQuest, many referenced from the [InQuest blog](http://blog.inquest.net).
- [Yara-Rules/rules](https://github.com/Yara-Rules/rules) - Community-maintained YARA rules.
- [advanced-threat-research/Yara-Rules](https://github.com/advanced-threat-research/Yara-Rules) - YARA rules from the McAfee Advanced Threat Research team.
- [citizenlab/malware-signatures](https://github.com/citizenlab/malware-signatures) - YARA rules for malware families seen in the Citizen Lab targeted threats project.
- [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) - YARA rules and EQL behavior rules used by Elastic Security for endpoint.
- [intezer/yara-rules](https://github.com/intezer/yara-rules) - YARA rules from Intezer.
- [kevthehermit/YaraRules](https://github.com/kevthehermit/YaraRules) - Personal YARA rule collection by kevthehermit.
- [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) - ReversingLabs YARA Rules.
- [x64dbg/yarasigs](https://github.com/x64dbg/yarasigs) - Various YARA signatures maintained by the x64dbg project.

## Tools

### IOC Tools

- [Neo23x0/yarGen](https://github.com/Neo23x0/yarGen) - Generator for YARA rules.
- [ninoseki/mitaka](https://github.com/ninoseki/mitaka#downloads) - Browser extension to look up IOCs and observables across many sources.
- [pedramamini/ThreatIngestor](https://github.com/pedramamini/ThreatIngestor) - Flexible framework for consuming threat intelligence.
- [pedramamini/iocextract](https://github.com/pedramamini/iocextract) - Advanced Indicator of Compromise (IOC) extractor.

### IOC Formats

- [MISP Malware Information Sharing Platform & Threat Sharing format](https://github.com/MISP/misp-rfc) - Specifications used in the MISP project including MISP core format.
- [MITRE Malware Attribute Enumeration and Characterization (MAEC™)](https://maecproject.github.io/) - A schema for understanding malware.
- [OASIS Structured Threat Information Expression (STIX™)](https://oasis-open.github.io/cti-documentation/) - A structured language and serialization format for exchanging cyber threat intelligence.
- [YARA](https://virustotal.github.io/yara/) - The pattern matching swiss knife for malware researchers (and everyone else).
- [mandiant/OpenIOC_1.1](https://github.com/mandiant/OpenIOC_1.1) - Revised schema, iocterms file and supporting documents for the draft OpenIOC 1.1 format.

## Footnotes

Archived and superseded sources are listed in [archived.md](archived.md).
