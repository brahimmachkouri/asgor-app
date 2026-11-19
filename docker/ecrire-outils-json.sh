#!/usr/bin/env bash
# Écrit outils.json (versions affichées par le service web et recopiées dans chaque
# rapport) à partir des versions réellement affichées par chaque outil de l'image.
# Même relevé que la tâche « Relever les versions des outils utilisés par le moteur »
# du playbook. Puis vérifie que chaque version est celle de versions-outils.json.
# Usage : ecrire-outils-json.sh <versions-outils.json> <outils.json à écrire>
set -euo pipefail

versions=$1
destination=$2

export COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_NO_INTERACTION=1
version() { timeout 30 "$@" </dev/null 2>&1 | grep -oE '[0-9]+[.][0-9]+[.][0-9]+' | head -n 1; }

python3 -I -c 'import json, sys; print(json.dumps(dict(zip(sys.argv[1::2], sys.argv[2::2])), indent=2))' \
  Gitleaks    "$(version gitleaks version)" \
  Composer    "$(version composer --version)" \
  pip-audit   "$(version pip-audit --version)" \
  OSV-Scanner "$(version osv-scanner --version)" \
  Trivy       "$(version trivy --version)" \
  Psalm       "$(version psalm --version)" \
  PHPStan     "$(version phpstan --version)" \
  Opengrep    "$(version opengrep --version)" \
  Bandit      "$(version bandit --version)" \
  > "$destination"

# Chaque outil doit afficher exactement la version épinglée (sinon : mauvais binaire).
python3 -I - "$versions" "$destination" <<'EOF'
import json, sys
attendu = json.load(open(sys.argv[1]))
releve = json.load(open(sys.argv[2]))
noms = {"Gitleaks": "gitleaks", "OSV-Scanner": "osv-scanner", "Trivy": "trivy",
        "Psalm": "psalm", "PHPStan": "phpstan", "Opengrep": "opengrep"}
ecarts = []
for affiche, cle in noms.items():
    if releve.get(affiche) != attendu["binaires"][cle]["version"]:
        ecarts.append(f"{affiche} : {releve.get(affiche)!r} au lieu de {attendu['binaires'][cle]['version']}")
for cle in ("bandit", "pip-audit"):
    affiche = "Bandit" if cle == "bandit" else "pip-audit"
    if releve.get(affiche) != attendu["outils_python"][cle]["version"]:
        ecarts.append(f"{affiche} : {releve.get(affiche)!r} au lieu de {attendu['outils_python'][cle]['version']}")
if not releve.get("Composer"):
    ecarts.append("Composer : version illisible")
if ecarts:
    sys.exit("Versions inattendues dans l'image : " + " ; ".join(ecarts))
print("outils.json : " + ", ".join(f"{k} {v}" for k, v in releve.items()))
EOF
