#!/usr/bin/env python3
"""Écrit un fichier requirements épinglé (versions exactes + sommes SHA256) depuis PyPI.

Sert aux outils Python d'ASGOR (asgor-ansible/files/outils-python/<outil>.txt) :

    python3 outils/epingler_python.py bandit bandit==1.9.4 PyYAML==6.0.3 ... \\
        > asgor-ansible/files/outils-python/bandit.txt

Donner l'outil ET toutes ses dépendances, chacune avec sa version exacte (par exemple
la sortie de « pip freeze » d'un environnement d'essai, sans pip). Pour chaque
paquet, le script lit l'API JSON de PyPI et écrit une somme SHA256 par fichier
publié (sdist et toutes les roues), comme pip-compile --generate-hashes.

Il refuse (code de sortie 1, rien d'écrit) une version publiée depuis moins de
14 jours (règle d'ASGOR) ou retirée (« yanked »).

Bibliothèque standard uniquement.
"""

import datetime
import json
import sys
import urllib.request

AGE_MIN_JOURS = 14


def fichiers_pypi(nom: str, version: str) -> list:
    with urllib.request.urlopen(f"https://pypi.org/pypi/{nom}/{version}/json", timeout=30) as r:
        return json.load(r)["urls"]


def main(arguments) -> int:
    if len(arguments) < 2 or any("==" not in a for a in arguments[1:]):
        print(__doc__, file=sys.stderr)
        return 2
    outil, specs = arguments[0], sorted(arguments[1:], key=str.lower)
    aujourd_hui = datetime.date.today()
    limite = aujourd_hui - datetime.timedelta(days=AGE_MIN_JOURS)
    lignes = [
        f"# Outil {outil} (venv /opt/asgor/venvs/{outil}) : dépendances épinglées",
        f"# Généré le {aujourd_hui:%d/%m/%Y} par outils/epingler_python.py depuis l'API JSON",
        "# de PyPI : une somme SHA256 par fichier publié (sdist et toutes les roues).",
        f"# Règle : versions publiées depuis au moins {AGE_MIN_JOURS} jours.",
        "# Installer avec : pip install --require-hashes --no-deps -r <ce fichier>",
        "",
    ]
    refus = []
    for spec in specs:
        nom, version = spec.split("==", 1)
        fichiers = fichiers_pypi(nom, version)
        if not fichiers:
            refus.append(f"{spec} : aucun fichier publié")
            continue
        if any(f.get("yanked") for f in fichiers):
            refus.append(f"{spec} : version retirée (yanked)")
            continue
        date = min(f["upload_time_iso_8601"][:10] for f in fichiers)
        if datetime.date.fromisoformat(date) > limite:
            refus.append(f"{spec} : publiée le {date}, moins de {AGE_MIN_JOURS} jours")
            continue
        sommes = sorted(f["digests"]["sha256"] for f in fichiers)
        lignes.append(f"# {nom} : publié le {date}, {len(fichiers)} fichier(s)")
        lignes.append(f"{nom}=={version} \\")
        lignes += [f"    --hash=sha256:{s}" + (" \\" if i < len(sommes) - 1 else "")
                   for i, s in enumerate(sommes)]
    if refus:
        print("Refusé :\n  " + "\n  ".join(refus), file=sys.stderr)
        return 1
    print("\n".join(lignes))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
