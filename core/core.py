from core.detect import fingerprint
from core.contain import isolate
from core.collect import collect_evidence
from core.decrypt import attempt_decrypt
from core.report import generate_report

class R3Core:
    def __init__(self):
        pass

    def handle_attack(self, epicenter):
        print("[1/4] Confinement...")
        zone = isolate(epicenter)

        print("[2/4] Collecte...")
        evidence = collect_evidence(zone)

        print("[3/4] Analyse...")
        profile = fingerprint(evidence)

        print("[4/4] Réponse...")
        if profile.get("decryptable"):
            result = attempt_decrypt(evidence)
            print(f"[✓] Déchiffrement : {result}")
        else:
            generate_report(evidence)
            print("[✓] Rapport généré")
