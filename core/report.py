import json

def generate_report(evidence):
    print("[📄] Génération du rapport IR...")
    with open("evidence/incident_report.json", "w") as f:
        json.dump(evidence, f, indent=2)
