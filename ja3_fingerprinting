# A script that parses output from ja3, in json format, to compare with list of known
# malicious ja3 hases of malicious applications/services.

import json

ja3_hashes_pcap = ""
ja3_hashes_dict = {}

with open("ja3Data.txt", 'r') as ja3_json_output:
	try:
		ja3_hashes_pcap = ja3_json_output.read()
		ja3_hashes_pcap = ja3_hashes_pcap.replace(" ", '').replace(']', "").replace('[', '').replace("},","}").replace('{', "~{").split('~')
		ja3_hashes_pcap.pop(0)
		count=0
		for d in ja3_hashes_pcap:
			ja3_hashes_pcap[count] = json.loads(d.strip())["ja3_digest"]
			count+=1
	except:
	  print("Error parsing ja3 data file")
	finally:
	 ja3_json_output.close()


with open("ja3prints/ja3fingerprint_filtered.json", 'r') as ja3_database_hashes:
	try:
		data = ja3_database_hashes.read()
		data = data.replace('{', "~{").split('~')
		data.pop(0)
		for d in data:
			ja3_hashes_dict[json.loads(d.strip())["ja3_hash"]] = json.loads(d.strip())["desc"]
	except:
		print("Error parsing ja3 hashes")
	finally:
	  ja3_database_hashes.close()

for hash in ja3_hashes_pcap:
	for key, value in ja3_hashes_dict.items():
		if(hash == key):
			print("App/Malware: ", value, " | ja3_hash: ", key)
