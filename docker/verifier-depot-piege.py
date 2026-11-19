"""Vérifie le rapport JSON d'une analyse du dépôt piège (depot-test-analyse).

Lancé par docker/ci.sh après « asgor-scan https://github.com/brahimmachkouri/depot-test-analyse ».
Les nombres de problèmes sont des minimums : le dépôt piège peut gagner des pièges,
et les bases de failles (domaine Dépendances) changent d'un jour à l'autre.
Code de retour 1 si un contrôle échoue.
"""

import json
import sys

OUTILS_ATTENDUS = {
    "secrets": {"Gitleaks"},
    "dependances": {"Composer Audit", "OSV-Scanner", "Trivy", "pip-audit"},
    "code": {"Bandit", "Opengrep", "Psalm"},
}
MINIMUMS = {"secrets": 4, "dependances": 1, "code": 9}
NOTE_ATTENDUE = "F"


def verifier(rapport: dict) -> list:
    echecs = []
    note = rapport["note"]
    if note["globale"] != NOTE_ATTENDUE:
        echecs.append(f"note globale {note['globale']}, attendu {NOTE_ATTENDUE}")
    if rapport["outils_non_lances"]:
        echecs.append(f"outils non lancés : {rapport['outils_non_lances']}")
    for nom, domaine in note["domaines"].items():
        if domaine["etat"] != "complet":
            echecs.append(f"domaine {nom} : état {domaine['etat']} ({domaine.get('raison')})")
        if domaine["outils_en_echec"]:
            echecs.append(f"domaine {nom} : outils en échec {domaine['outils_en_echec']}")
        manquants = OUTILS_ATTENDUS.get(nom, set()) - set(domaine["outils_reussis"])
        if manquants:
            echecs.append(f"domaine {nom} : outils non réussis {sorted(manquants)}")
    for nom, minimum in MINIMUMS.items():
        trouves = sum(1 for p in rapport["problemes"] if p["domaine"] == nom)
        if trouves < minimum:
            echecs.append(f"domaine {nom} : {trouves} problème(s), au moins {minimum} attendus")
    return echecs


def main() -> int:
    with open(sys.argv[1], encoding="utf-8") as f:
        rapport = json.load(f)
    echecs = verifier(rapport)
    for e in echecs:
        print(f"ÉCHEC  {e}")
    if not echecs:
        domaines = rapport["note"]["domaines"]
        print(f"OK  note {rapport['note']['globale']}, "
              + ", ".join(f"{n} {d['lettre']} ({d['problemes']})" for n, d in domaines.items()))
    return 1 if echecs else 0


if __name__ == "__main__":
    sys.exit(main())
