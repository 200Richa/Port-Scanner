import nmap3
nmap = nmap3.NmapScanTechniques()

results = nmap.nmap_syn_scan()

print(results)