#!/usr/bin/env bash
# Télécharge les binaires d'ASGOR listés dans versions-outils.json, pour une architecture,
# vérifie chaque somme SHA256 et arrête la construction au moindre écart.
# Usage (étape de construction du Dockerfile) :
#   installer-binaires.sh <versions-outils.json> <linux/amd64|linux/arm64> <dossier de sortie>
set -euo pipefail

versions=$1
plateforme=$2
sortie=$3

case "$plateforme" in
  linux/amd64|linux/arm64) ;;
  *) echo "Architecture non prise en charge : $plateforme" >&2; exit 1 ;;
esac

travail=$(mktemp -d)
mkdir -p "$sortie"

for nom in $(jq -r '.binaires | keys[]' "$versions"); do
  outil=$(jq -c --arg n "$nom" '.binaires[$n]' "$versions")
  # Un PHAR ne dépend pas de l'architecture : entrée « tous ».
  entree=$(jq -c --arg p "$plateforme" '.[$p] // .tous // empty' <<<"$outil")
  if [ -z "$entree" ]; then
    echo "$nom : aucune version pour $plateforme" >&2
    exit 1
  fi
  url=$(jq -r '.url' <<<"$entree")
  somme=$(jq -r '.sha256' <<<"$entree")
  membre=$(jq -r '.archive // empty' <<<"$outil")
  version=$(jq -r '.version' <<<"$outil")

  [[ "$url" == https://github.com/* ]] || { echo "$nom : adresse refusée ($url)" >&2; exit 1; }
  [[ "$somme" =~ ^[0-9a-f]{64}$ ]] || { echo "$nom : somme SHA256 invalide" >&2; exit 1; }

  fichier="$travail/$nom.telecharge"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$fichier" "$url"
  echo "$somme  $fichier" | sha256sum -c --quiet - \
    || { echo "$nom $version : SOMME SHA256 FAUSSE, construction arrêtée" >&2; exit 1; }

  if [ -n "$membre" ]; then
    # Archive : on n'extrait que le binaire attendu.
    tar -xzf "$fichier" -C "$travail" "$membre"
    install -m 0755 "$travail/$membre" "$sortie/$nom"
  else
    install -m 0755 "$fichier" "$sortie/$nom"
  fi
  echo "$nom $version ($plateforme) : somme vérifiée"
done
