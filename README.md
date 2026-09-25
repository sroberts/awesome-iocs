# Awesome IOCs [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

An [awesome](https://github.com/sindresorhus/awesome) collection of indicators of compromise (and a few IOC related tools).

## Contents

- [IOCs](https://github.com/sroberts/awesome-iocs#iocs)
  - [Indicators](https://github.com/sroberts/awesome-iocs#indicators)
  - [Snort Signatures](https://github.com/sroberts/awesome-iocs#snort-signatures)
  - [Yara Signatures](https://github.com/sroberts/awesome-iocs#yara-signatures)
- [Tools](https://github.com/sroberts/awesome-iocs#tools)
  - [IOC Tools](https://github.com/sroberts/awesome-iocs#ioc-tools)
  - [IOC Formats](https://github.com/sroberts/awesome-iocs#ioc-formats)

## IOCs

### Indicators

- [0x27/linux.mirai](https://github.com/0x27/linux.mirai) - Leaked Linux.Mirai Source Code for Research/IoC Development Purposes.
- [CyberBriefing IOC API](https://cyberbriefing.info) - Vendor-operated REST API aggregating active IOCs from public feeds (AlienVault OTX, Abuse.ch URLhaus, ThreatFox, CISA KEV, Tor exit nodes, OpenPhish); free tier requires an API key.
- [Extuno Malicious Package Database](https://extuno.com/malicious-db) - Vendor-operated database of malicious browser extensions and packages across 12 ecosystems (Chrome, Firefox, VS Code, npm, PyPI, WordPress and others), aggregated from OSV, OpenSSF and vendor feeds, with a free web lookup and JSON endpoint.
- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) - Signature base for my scanner tools.
- [PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information](https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information) - Indicators from Unit 42 Public Reports.
- [ThreatCluster Public IOC Feed](https://threatcluster.io/feeds) - Vendor-operated feed of indicators extracted from clustered public reporting, available as TXT, CSV and JSON.
- [aptnotes/data](https://github.com/aptnotes/data) - APTnotes data.
- [botherder/targetedthreats](https://github.com/botherder/targetedthreats) - Collection of IOCs related to targeting of civil society.
- [circl/osint-feed](https://www.circl.lu/doc/misp/feed-osint/) - Open Source Intelligence for MISP.
- [citizenlab/malware-indicators](https://github.com/citizenlab/malware-indicators) - Citizen Lab Malware Reports.
- [eset/malware-ioc](https://github.com/eset/malware-ioc) - Indicators of Compromises (IOC) of our various investigations.
- [jasonmiacono/IOCs](https://github.com/jasonmiacono/IOCs) - Indicators of compromise for threat intelligence.
- [mandiant/iocs](https://github.com/mandiant/iocs) - FireEye Publicly Shared Indicators of Compromise (IOCs). Archived; last updated 2019.
- [nshc-threatrecon/IoC-List](https://github.com/nshc-threatrecon/IoC-List) - NSHC ThreatRecon IoC Repository.
- [swisscom/detections](https://github.com/swisscom/detections) - Threat intelligence information and threat detection indicators (IOC, IOA) shared by Swisscom CSIRT. Archived; last updated 2020.
- [thirdeyeintelligence/IOCs-in-CSV-format](https://github.com/thirdeyeintelligence/IOCs-in-CSV-format) - The repository contains IOCs in CSV format for APT, Cyber Crimes, Malware and Trojan and whatever I found as part of hunting and research.

### Snort Signatures

- [Snort Downloads](https://www.snort.org/downloads) - Signatures for the Snort (& Suricata) Intrusion Detection System.
- [kingtuna/Signatures](https://github.com/kingtuna/Signatures) - A mixture of snort and suricata signatures.

### Yara Signatures

- [0pc0deFR/YaraRules](https://github.com/0pc0deFR/YaraRules) - Multiple rules for yara-project for detect compiler/packer/protector. Archived.
- [InQuest/yara-rules](https://github.com/InQuest/yara-rules) - A collection of Yara rules we wish to share with the world, most probably referenced from [http://blog.inquest.net](http://blog.inquest.net).
- [Yara-Rules/rules](https://github.com/Yara-Rules/rules) - Repository of yara rules.
- [advanced-threat-research/Yara-Rules](https://github.com/advanced-threat-research/Yara-Rules) - Repository of YARA rules made by McAfee ATR Team.
- [citizenlab/malware-signatures](https://github.com/citizenlab/malware-signatures) - Yara rules for malware families seen as part of targeted threats project.
- [intezer/yara-rules](https://github.com/intezer/yara-rules) - Yara rules from Intezer.
- [kevthehermit/YaraRules](https://github.com/kevthehermit/YaraRules) - My Yara Rules Collection.
- [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) - ReversingLabs YARA Rules.
- [x64dbg/yarasigs](https://github.com/x64dbg/yarasigs) - Various Yara signatures (possibly to be included in a release later).

## Tools

### IOC Tools

- [Neo23x0/yarGen](https://github.com/Neo23x0/yarGen) - yarGen is a generator for YARA rules.
- [YahooArchive/PyIOCe](https://github.com/YahooArchive/PyIOCe) - Python IOC Editor. Archived.
- [mandiant/ioc_writer](https://github.com/mandiant/ioc_writer) - Provide a python library that allows for basic creation and editing of OpenIOC objects. Archived.
- [ninoseki/mitaka](https://github.com/ninoseki/mitaka#downloads) - Browser extension to lookup IoCs/observables on many sources.
- [pedramamini/ThreatIngestor](https://github.com/pedramamini/ThreatIngestor) - Flexible framework for consuming threat intelligence.
- [pedramamini/iocextract](https://github.com/pedramamini/iocextract) - Advanced Indicator of Compromise (IOC) extractor.

### IOC Formats

- [MISP Malware Information Sharing Platform & Threat Sharing format](https://github.com/MISP/misp-rfc) - Specifications used in the MISP project including MISP core format.
- [Mitre Cyber Observable eXpression (CybOX™)](https://cyboxproject.github.io/) - This site contains archived CybOX documentation.
- [Mitre Malware Attribute Enumeration and Characterization (MAEC™)](https://maecproject.github.io/) - A schema for understanding malware.
- [Mitre Structured Threat Information eXpression (STIX™)](https://stixproject.github.io/) - A structured language for cyber threat intelligence.
- [Yara](https://virustotal.github.io/yara/) - The pattern matching swiss knife for malware researchers (and everyone else).
- [fireeye/OpenIOC_1.1](https://github.com/fireeye/OpenIOC_1.1) - This repository contains a revised schema, iocterms file, and other supporting documents which are the basis for a draft of a revised version of OpenIOC that we are calling OpenIOC 1.1.

## License

This content uses the CC0 1.0 Universal (CC0 1.0)
Public Domain Dedication license.
