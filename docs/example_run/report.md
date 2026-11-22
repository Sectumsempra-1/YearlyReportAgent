# Yearly security report 2026

Compared with 2025.

## Executive summary

**Credential theft incidents surged significantly while high severity attacks rose, marking a shift from traditional ransomware threats to more acute credential-focused risks targeting the energy sector.**

### Headline numbers

- Credential theft incidents increased by 80.4% [F-001] to 11,663 [F-001] attacks in 2026.
- Ransomware attacks fell by 9.2% [F-002] to 1,940 [F-002], the only attack type to decline.
- LummaStealer detections reached 117,831 [F-025], representing 25.6% [F-025] of all malware traffic with potential overcounting due to product summation.
- High severity incidents increased by 16.4% [F-023] and account for 37.3% [F-023] of all blocked attacks in 2026, though totals may be summed across products.
- The Energy sector absorbed 1,890,700 [F-022] blocked attacks with a 34.0% [F-022] share of total volume and potential overcounting issues across products.
- Brazil rose to rank 3 [F-024] in aggregate data covering all products with a 246.4% [F-024] increase based on IP geolocation not attacker attribution.

### Credential Theft Emerges as Primary Risk

Incidents of credential theft rose sharply compared to last year, indicating a critical shift in attacker tactics that requires immediate monitoring.

### New Malware Dominates the Threat Landscape

A new malware family became the leading threat detected, while other attack types showed varying levels of decline or growth.

### Energy Sector Faces Intensified Geographic Attacks

The energy sector absorbed the highest volume of attack traffic while new sources like Brazil emerged as major contributors to malicious traffic.

### Top recommendations

- Monitor the Energy sector as it remained the most targeted industry with 1,890,700 [F-022] blocked attacks representing a 34.0% [F-022] share of total volume, where totals may be summed across products.
- Prioritize defenses against high severity incidents as they increased 16.4% [F-023] to account for 2,071,373 [F-023] blocked attacks in 2026 and now make up 37.3% [F-023] of all blocked attacks.
- Defend against LummaStealer malware as it emerged as the most prevalent malware family in 2026 with 117,831 [F-025] detections accounting for a 25.6% [F-025] share.

## Product performance

### EDR Performance

The EDR product blocked credential_theft attacks 11,663 [F-001] times in 2026. This represented an increase of 80.4% [F-001] from 6,464 [F-001]. Ransomware is the only attack type to decline, with a decrease of 9.2% [F-002], dropping from 2,137 [F-002] to 1,940 [F-002].

### Firewall Performance

Malware download attacks increased by 24.1% [F-012], the largest year-over-year change among all attack types. The count was 223,501 [F-012] in 2026, up from 180,156 [F-012]. Brute force attacks decreased by 29.3% [F-013], falling from 3,591,554 [F-013] to 2,539,855 [F-013]. This product reports only blocked events, so a block rate cannot be calculated.

## Top malware

LummaStealer emerged as the most prevalent malware family in 2026 with 117,831 [F-025] detections and a 25.6% [F-025] share of all malware. This figure sums across products, so one attack can be seen by more than one product (e.g. email gateway and EDR) and this may overcount attacks [F-025]. Some vendor malware names have no common family mapping; see unmapped_malware() [F-025].

On EDR endpoints, LummaStealer is a new malware family in 2026 with rank 1 [F-005] and 10,544 [F-005] detections, which was 23.1% [F-005] of the share of all malware [F-005].

At the Email Gateway, LummaStealer emerged as a new malware family in 2026, blocking 32,587 [F-011] instances which accounted for 26.0% [F-011] of all blocked malware.

A Firewall detected LummaStealer with a volume of 74,700 [F-018], accounting for 25.8% [F-018] of all malware detections.

Win32/Kryptik.gen is a new unmapped malware family on EDR endpoints with 3,204 [F-006] detections.

## Source countries

### Geographic Origins of Attack Traffic

In aggregate data covering all products, Brazil rose from rank 10 [F-024] to rank 3 [F-024] with a 246.4% [F-024] increase in attack volume. These figures are based on IP geolocation of the attacking infrastructure, not attribution of the attacker; VPNs, proxies and compromised hosts are common. Because data is summed across products, one attack can be seen by more than one product (e.g. email gateway and EDR), so this may overcount attacks.

For firewall traffic, China remained the top source country of attacks in 2026, accounting for 895,100 [F-017] volume and 20.0% [F-017] of all attack volume. Brazil emerged as the second-largest source country of attacks with a 211.6% [F-016] increase from the previous year, reaching 668,293 [F-016] volume and representing 14.9% [F-016] of firewall traffic.

For email gateway products, Chinese-origin attacks increased by 55.7% [F-010] to become the top attacking country with 205,490 [F-010] blocked incidents and a share of 20.0% [F-010]. Brazil became the third-largest attacking country in 2026, jumping from rank 10 [F-009] to rank 3 [F-009] with a 549.0% [F-009] increase in attacks, accounting for 154,209 [F-009] incidents and a share of 15.0% [F-009].

## Trends

### Monthly Activity Patterns

EDR metrics peaked in March and were lowest in October [F-003]. The email gateway blocked 185,566 [F-007] attacks in March, with an increase of 106,670 [F-007] from the previous month and a change of 135.2% [F-007].

### Changes in Attack Type Popularity

Brute force attacks declined 29.3% [F-019] year-over-year to 2,539,855 [F-019] blocks. Phishing attacks surged by 83.2% [F-021] to 849,597 [F-021] blocks, representing the largest increase among all attack types. These totals are summed across products, so one attack can be seen by more than one product (e.g., email gateway and EDR), which may overcount attacks.

## Recommendations

- Monitor the Energy sector as it remained the most targeted industry with 1,890,700 [F-022] blocked attacks representing a 34.0% [F-022] share of total volume. These figures are summed across products so one attack can be seen by more than one product such as an email gateway or EDR which may overcount attacks.
- Prioritize defenses against high severity incidents as they increased 16.4% [F-023] to account for 2,071,373 [F-023] blocked attacks in 2026 and now make up 37.3% [F-023] of all blocked attacks.
- Defend against LummaStealer malware as it emerged as the most prevalent malware family in 2026 with 117,831 [F-025] detections accounting for a 25.6% [F-025] share. Note that these figures are summed across products and some vendor malware names have no common family mapping so classification may be incomplete.

## Methodology and data gaps

This report covers 2026 compared with 2025. It is based on monthly aggregated counts delivered by each product team, with no client names. Each delivery was validated before loading; a file with any invalid row was rejected as a whole.

**Data sources** (product, and the years loaded):

- EDR (Endpoint): 2025 and 2026
- Email Gateway (Email): 2025 and 2026
- Firewall (Network): 2025 and 2026

Every figure in this report comes from a read-only query of that data (`attack_type_changes`, `monthly_series`, `product_summary`, `sector_breakdown`, `severity_breakdown`, `top_countries`, `top_malware`, `unmapped_malware`) and is checked against the query before the report is published. Each figure is traceable to its finding.

**Caveats.**

- Some vendor malware names have no common family mapping; see unmapped_malware().
- Based on IP geolocation of the attacking infrastructure, not attribution of the attacker. VPNs, proxies and compromised hosts are common.
- This product reports only blocked events, so a block rate cannot be calculated.
- Summed across products. One attack can be seen by more than one product (e.g. email gateway and EDR), so this may overcount attacks.

**MITRE ATT&CK.** Findings were mapped to techniques from MITRE ATT&CK for Enterprise v20.1. Mappings with low confidence were left out of this report and listed for human review.

Techniques referenced:

- T1059 Command and Scripting Interpreter
- T1071 Application Layer Protocol
- T1074 Data Staged
- T1078 Valid Accounts
- T1110 Brute Force
- T1486 Data Encrypted for Impact
- T1566 Phishing
- T1569 System Services

**Data gaps.** Missing or unmapped data is reported here, never estimated.

- None reported.
