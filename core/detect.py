def fingerprint(evidence):
    print("[🔍] Analyse du variant ransomware...")
    for f in evidence.get("files", []):
        if "README" in f or "decrypt" in f:
            return {"variant": "LockBit 3.0", "decryptable": True}
    return {"variant": "Unknown", "decryptable": False}
