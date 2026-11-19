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
  docker compose exec -T worker asgor-scan "$PIEGE" | tee "$TEMP/piege.log"
  local rapport
  rapport=$(sed -n 's/^Rapport : //p' "$TEMP/piege.log")
  [ -n "$rapport" ]
  docker compose exec -T worker cat "$rapport" > "$TEMP/piege.json"
  python3 docker/verifier-depot-piege.py "$TEMP/piege.json"

  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::endgroup::"; fi
  echo "Image vérifiée ($(uname -m))."
}

case "${1:-}" in
  construire) construire "${2:-}" ;;
  verifier) verifier ;;
  *) echo "usage : $0 construire [version] | verifier" >&2; exit 2 ;;
esac
