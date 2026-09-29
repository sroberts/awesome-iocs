# Awesome IOCs [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

<a href="https://en.wikipedia.org/wiki/Indicator_of_compromise"><img src="media/header.svg" width="100%" alt="Network graph with one node flagged as an indicator of compromise"></a>

Forensic artifacts, such as file hashes, domains, IP addresses and detection signatures, that identify malicious activity on a system or network.

## Contents

- [IOCs](#iocs)
  - [Indicators](#indicators)
  - [Snort and Suricata Signatures](#snort-and-suricata-signatures)
  - [YARA Signatures](#yara-signatures)
- [Tools](#tools)
  - [IOC Tools](#ioc-tools)
  - [IOC Formats](#ioc-formats)

## IOCs

### Indicators

- [CIRCL OSINT Feed](https://www.circl.lu/doc/misp/feed-osint/) - CIRCL's public MISP feed of indicators from open-source reporting, ready to subscribe to from a MISP instance.
- [Cisco-Talos/IOCs](https://github.com/Cisco-Talos/IOCs) - IOCs from Cisco Talos.
- [CyberBriefing IOC API](https://cyberbriefing.info) - Vendor-operated REST API that puts active IOCs from public feeds (AlienVault OTX, Abuse.ch URLhaus, ThreatFox, CISA KEV, Tor exit nodes, OpenPhish) behind one query interface; free tier requires an API key.
- [DomainTools-Investigations/Malware-and-Scams](https://github.com/DomainTools-Investigations/Malware-and-Scams) - IOCs from DomainTools for malware and scams.
- [DomainTools-Investigations/Nation-State-Threats](https://github.com/DomainTools-Investigations/Nation-State-Threats) - IOCs from DomainTools for nation-state threats.
- [Extuno Malicious Package Database](https://extuno.com/malicious-db) - Vendor-operated database of malicious browser extensions and packages across 12 ecosystems (Chrome, Firefox, VS Code, npm, PyPI, WordPress and others), aggregated from OSV, OpenSSF and vendor feeds, for checking software supply-chain exposure; free web lookup and JSON endpoint.
- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) - YARA rules and IOCs behind the LOKI and THOR Lite scanners, curated for a low false-positive rate and updated frequently.
- [PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information](https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information) - IOCs and supporting data for Palo Alto Networks Unit 42 threat research articles, so indicators can be traced back to their write-up.
- [ThreatCluster Public IOC Feed](https://threatcluster.io/feeds) - Vendor-operated feed of indicators extracted from clustered public reporting, available as TXT, CSV and JSON.
- [aptnotes/data](https://github.com/aptnotes/data) - Index of public reports on APT campaigns sorted by year, useful for tracing indicators back to the original vendor reporting.
- [botherder/targetedthreats](https://github.com/botherder/targetedthreats) - Network indicators from reports on the targeting of civil society, published as CSV, JSON and generated Snort rules.
- [citizenlab/malware-indicators](https://github.com/citizenlab/malware-indicators) - Indicators from Citizen Lab investigations into targeted attacks on civil society, one directory per report.
- [cystack/stealer-fingerprints](https://github.com/cystack/stealer-fingerprints) - Fingerprints of infostealer log formats (banner strings, field signatures, YARA rules) for 30+ families including RedLine, Vidar, Lumma and StealC, for identifying which stealer produced a leaked log.
- [eset/malware-ioc](https://github.com/eset/malware-ioc) - Indicators from ESET research publications, one directory per report and actively updated.
- [hvs-consulting/ioc_signatures](https://github.com/hvs-consulting/ioc_signatures) - IOCs, CSV context and YARA rules from HvS-Consulting incident response work, organized by threat actor or campaign for threat hunting.
- [trilwu/apttrail](https://github.com/trilwu/apttrail) - APT indicators that carry the actor they belong to, its MITRE ATT&CK group ID, when they first appeared and the report that published them.
- [volexity/threat-intel](https://github.com/volexity/threat-intel) - IOCs from Volexity public threat research blog posts, organized by year and post.

### Snort and Suricata Signatures

- [Emerging Threats Open](https://rules.emergingthreats.net/open/) - Free Proofpoint Emerging Threats ruleset for Snort and Suricata, a common baseline for network intrusion detection.
- [Snort Downloads](https://www.snort.org/downloads) - Official Snort rule sets, many of which also work with Suricata.

### YARA Signatures

- [InQuest/yara-rules](https://github.com/InQuest/yara-rules) - YARA rules from InQuest research, intended for hunting rather than production detection; many are referenced from the [InQuest blog](http://blog.inquest.net).
- [Yara-Rules/rules](https://github.com/Yara-Rules/rules) - Community-compiled YARA ruleset classified by threat type, a broad starting point for hunting.
- [advanced-threat-research/Yara-Rules](https://github.com/advanced-threat-research/Yara-Rules) - YARA rules that accompany Trellix Advanced Threat Research (formerly McAfee ATR) blog posts and investigations.
- [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) - YARA rules and EQL behavior rules used by Elastic Security for endpoint, with coverage mapped to MITRE ATT&CK.
- [intezer/yara-rules](https://github.com/intezer/yara-rules) - YARA rules from Intezer malware research.
- [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) - Detection-focused YARA rules from ReversingLabs threat analysts, written with the stated aim of zero false positives.
- [x64dbg/yarasigs](https://github.com/x64dbg/yarasigs) - YARA signatures for identifying packers, compilers and crypto constants, useful during reverse engineering.

## Tools

### IOC Tools

- [Neo23x0/yarGen](https://github.com/Neo23x0/yarGen) - Generates YARA rules from malware samples while filtering out strings common in goodware.
- [ninoseki/mitaka](https://github.com/ninoseki/mitaka#downloads) - Browser extension that looks up a selected IOC across many OSINT and scanning services from the context menu.
- [pedramamini/ThreatIngestor](https://github.com/pedramamini/ThreatIngestor) - Extendable framework that extracts and aggregates IOCs from threat feeds and passes them to other tools.
- [pedramamini/iocextract](https://github.com/pedramamini/iocextract) - Extracts IOCs from text, including defanged URLs, IP addresses and hashes.

### IOC Formats

- [MISP Malware Information Sharing Platform & Threat Sharing format](https://github.com/MISP/misp-rfc) - Specifications for the MISP core format and related formats, used to exchange indicators between MISP and other platforms.
- [MITRE Malware Attribute Enumeration and Characterization (MAEC™)](https://maecproject.github.io/) - Schema for encoding malware behaviors, capabilities and attributes.
- [OASIS Structured Threat Information Expression (STIX™)](https://oasis-open.github.io/cti-documentation/) - A structured language and serialization format for exchanging cyber threat intelligence.
- [YARA](https://virustotal.github.io/yara/) - Pattern-matching language and tool for identifying and classifying malware, used by most signature collections in this list.

## Related Lists

- [Awesome Detection Engineering](https://github.com/infosecB/awesome-detection-engineering#readme) - Designing, building and operating detection controls.
- [Awesome Incident Response](https://github.com/meirwah/awesome-incident-response#readme) - Tools and resources for security incident response.
- [Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis#readme) - Tools and resources for analyzing malware.
- [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence#readme) - Threat intelligence sources, formats and platforms.
- [Awesome YARA](https://github.com/InQuest/awesome-yara#readme) - YARA rules, tools and resources.

## Contributing

Contributions are welcome. Read the [contribution guidelines](CONTRIBUTING.md) before opening a pull request.

## Footnotes

Archived, unmaintained and superseded sources are listed in [archived.md](archived.md).
