import os
import hashlib

def collect_evidence(zone):
    os.makedirs("evidence", exist_ok=True)
    collected = {
        "host": zone["host"],
        "files": [],
        "memory_dump": "memdump.img",
        "logs": "syslog.log"
    }

    # Simule collecte de fichiers
    for f in ["README.txt", "encrypted.docx", "malware.bin"]:
        path = f"evidence/{f}"
        with open(path, "w") as out:
            out.write("dummy data")
        collected["files"].append(path)

    return collected
