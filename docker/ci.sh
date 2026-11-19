#!/bin/bash
# Construction et vérification de l'image, pour l'architecture de la machine.
# Lancé par GitHub Actions (.github/workflows/image.yml) ; marche aussi sur un poste.
#   bash docker/ci.sh construire [version]   construit asgor:developpement
#   bash docker/ci.sh verifier               tests, services, autotest, page web, dépôt piège
# « verifier » démarre les services de compose.yaml (volumes à noms fixes asgor-*) :
# sur un poste, ne pas le lancer si ASGOR y tourne déjà avec des données à garder.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=asgor:developpement
PIEGE=https://github.com/brahimmachkouri/depot-test-analyse
TEMP=${RUNNER_TEMP:-$(mktemp -d)}
# Groupe propriétaire du socket Docker (Linux) ; 0 sur Docker Desktop.
DOCKER_GID=${DOCKER_GID:-$(stat -c %g /var/run/docker.sock 2>/dev/null || echo 0)}
export DOCKER_GID

titre() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::endgroup::"; echo "::group::$1"; else echo "== $1"; fi
}

construire() {
  local version=${1:-developpement}
  titre "Construction de l'image ($version, $(uname -m))"
  docker version --format 'Docker {{.Server.Version}} (API {{.Server.APIVersion}})'
  # Sans attestation BuildKit dans l'image : la provenance est attestée à part, à la
  # publication (GitHub). Chaque architecture reste ainsi une image simple.
  docker buildx build --load --provenance=false --sbom=false \
    --build-arg VERSION_ASGOR="$version" \
    --build-arg COMMIT_ASGOR="$(git rev-parse HEAD 2>/dev/null || echo inconnu)" \
    -t "$IMAGE" .
}

attendre() {  # attendre <description> <secondes> <commande…>
  local quoi=$1 delai=$2 debut=$SECONDS
  shift 2
  until "$@" >/dev/null 2>&1; do
    if (( SECONDS - debut > delai )); then
      echo "Délai dépassé : $quoi" >&2
      docker compose ps -a >&2 || true
      docker compose logs --no-color --tail 50 >&2 || true
      return 1
    fi
    sleep 3
  done
}

code_http() {  # code_http <hôte> : code de la page d'accueil avec cet en-tête Host
  curl -s -o /dev/null -w '%{http_code}' -H "Host: $1" http://127.0.0.1:8000/
}

limite_api() {  # « <restantes> <secondes avant le retour> » ; cette requête ne compte pas
  curl -s --max-time 20 -H "User-Agent: asgor-ci" https://api.github.com/rate_limit \
    | python3 -I -c '
import json, sys, time
c = json.load(sys.stdin)["resources"]["core"]
print(c["remaining"], max(0, int(c["reset"] - time.time())))' 2>/dev/null || echo "inconnue"
}

attendre_limite_api() {  # attendre_limite_api <attente maximale en secondes>
  local etat restantes delai
  etat=$(limite_api)
  echo "Limite de l'API GitHub : $etat (requêtes restantes, secondes avant le retour)"
  read -r restantes delai <<< "$etat"
  [ "$restantes" = inconnue ] && return 0
  (( restantes > 0 )) && return 0
  if (( delai > $1 )); then
    echo "Limite de l'API GitHub atteinte pour cette adresse, retour dans $(( delai / 60 )) min : relancer plus tard." >&2
    return 1
  fi
  echo "Limite de l'API GitHub atteinte : attente de $delai s."
  sleep $(( delai + 5 ))
}

verifier() {
  titre "Tests du moteur (dans l'image)"
  # ASGOR_LANCEUR vide : les tests utilisent le lanceur simulé, pas le filtre.
  docker run --rm --network none --user 10001:10001 --group-add 10002 \
    -e HOME=/tmp -e ASGOR_LANCEUR= \
    -v "$PWD/moteur/tests:/opt/asgor/moteur/tests:ro" -w /opt/asgor/moteur \
    --entrypoint python3 "$IMAGE" -m unittest discover -s tests -t .

  titre "Tests du service web (dans l'image)"
  # Dépendances des tests (client de FastAPI) épinglées par somme SHA256, dans /tmp.
  docker run --rm --user 10001:10001 --group-add 10002 -e HOME=/tmp -e ASGOR_LANCEUR= \
    -v "$PWD/web/tests_web:/opt/asgor/web/tests_web:ro" \
    -v "$PWD/web/requirements-tests.txt:/tmp/requirements-tests.txt:ro" \
    -w /opt/asgor/web --entrypoint sh "$IMAGE" -c '
      /opt/asgor/venvs/web/bin/pip install -q --disable-pip-version-check --require-hashes \
        --no-deps --only-binary=:all: --target /tmp/t -r /tmp/requirements-tests.txt
      PYTHONPATH=/tmp/t:/opt/asgor/web:/opt/asgor/moteur \
        /opt/asgor/venvs/web/bin/python -m unittest discover -s tests_web -t .'

  titre "Règles Semgrep absentes de l'image"
  docker run --rm --network none --entrypoint sh "$IMAGE" -c \
    'test -z "$(ls -A /opt/asgor/regles)"'
  echo "OK"

  titre "Démarrage des services (DOCKER_GID=$DOCKER_GID)"
  docker compose up -d --no-build
  # Le worker installe les règles Semgrep à son premier démarrage (par le filtre).
  attendre "installation des règles Semgrep" 600 \
    docker compose exec -T worker test -e /opt/asgor/regles/semgrep-rules/actuel
  attendre "service web" 120 curl -sf -o /dev/null http://127.0.0.1:8000/
  docker compose ps

  titre "Autotest d'isolation"
  docker compose exec -T worker python3 -m asgor_moteur.autotest_docker

  titre "Service web : adresse d'écoute et en-tête Host"
  local publie
  publie=$(docker compose port web 8000)
  echo "port publié : $publie"
  [ "$publie" = "127.0.0.1:8000" ]
  [ "$(code_http 127.0.0.1:8000)" = 200 ]
  [ "$(code_http localhost:8000)" = 200 ]
  [ "$(code_http exemple.invalid)" = 421 ]
  [ "$(code_http 127.0.0.1.nip.io:8000)" = 421 ]
  echo "OK"

  titre "Analyse du dépôt piège"
  # Le moteur demande la description du dépôt à l'API de GitHub, sans jeton : 60 requêtes
  # par heure et par adresse IP. Les machines de GitHub Actions partagent leurs adresses :
  # la limite peut être déjà atteinte (vu le 19/11/2026). On attend son retour s'il est proche.
  attendre_limite_api 1200
  docker compose exec -T worker asgor-scan "$PIEGE" | tee "$TEMP/piege.log"
  local rapport
  rapport=$(sed -n 's/^Rapport : //p' "$TEMP/piege.log")
  if [ -z "$rapport" ]; then
    echo "Analyse du dépôt piège impossible. Limite de l'API GitHub pour cette adresse : $(limite_api)" >&2
    return 1
  fi
  docker compose exec -T worker cat "$rapport" > "$TEMP/piege.json"
  python3 docker/verifier-depot-piege.py "$TEMP/piege.json"

  titre "Rapport du dépôt piège (JSON compressé, pour comparaison avec une autre installation)"
  # Pour le relire : copier les lignes entre les deux repères, puis base64 -d | gunzip.
  # Secrets masqués (4 premiers caractères), et ceux d'un dépôt de test public.
  # Le journal est public : le texte des règles Semgrep (explication, références) est
  # remplacé par sa somme SHA256, car leur licence interdit de les distribuer. La
  # comparaison reste possible en calculant la même somme sur l'autre rapport.
  python3 -I -c '
import hashlib, json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
for p in r["problemes"]:
    if "Opengrep" in p.get("outils", []):
        for cle in ("explication", "references"):
            texte = json.dumps(p.get(cle), ensure_ascii=False, sort_keys=True)
            p[cle] = "sha256:" + hashlib.sha256(texte.encode()).hexdigest()
json.dump(r, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False)
' "$TEMP/piege.json" "$TEMP/piege-public.json"
  echo "--- début du rapport ---"
  gzip -9c "$TEMP/piege-public.json" | base64 | fold -w 76
  echo "--- fin du rapport ---"

  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::endgroup::"; fi
  echo "Image vérifiée ($(uname -m))."
}

case "${1:-}" in
  construire) construire "${2:-}" ;;
  verifier) verifier ;;
  *) echo "usage : $0 construire [version] | verifier" >&2; exit 2 ;;
esac
