# Answer key: planted patterns in the dummy data

The data was generated with these patterns on purpose. A good agent run should
find them without being told. **Keep this file away from Claude Code until the evaluation step.** Use it
to score their output.

1. **Total blocked fell about 6% year over year, while most attack types rose.** The drop comes from firewall brute-force attempts (about -29%), the largest category by volume. A report that only says "attacks went down" missed the real story.
2. **Phishing up about 83%,** with a spike in March 2026 (about 2.5 times a normal month).
3. **LummaStealer is new in 2026 and is now the #1 malware family,** ahead of AgentTesla (last year's #1).
4. **Akira is new in 2026 and overtook LockBit** among ransomware families. Ransomware detections overall fell about 9%.
5. **Credential theft on endpoints up about 80%,** which fits the rise of an information stealer (LummaStealer).
6. **Brazil rose from #10 to #3** among source countries, nearly tied with Russia at #2.
7. **Energy is the most targeted sector,** and its share grew from about 30% to 34%.
8. **Data gap:** EDR reports `Win32/Kryptik.gen`, which isn't in the alias list. The report should flag it as unmapped, not drop it silently or guess a family.
9. **Trap:** adding blocked counts across all products overstates attacks, because one attack can be seen by several products. The report should say so, or report per product.
10. **Ingestion test:** `exports_bad/edr_2026_resubmission.csv` has an invalid month, an invalid action, a full country name instead of an ISO code, and a negative count. It must be rejected as a whole.

