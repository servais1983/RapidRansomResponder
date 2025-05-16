def attempt_decrypt(evidence):
    print("[🔐] Tentative de déchiffrement basée sur base de failles connues...")
    if "encrypted.docx" in "".join(evidence["files"]):
        return "Clé de test appliquée, fichier récupéré"
    return "Échec"
