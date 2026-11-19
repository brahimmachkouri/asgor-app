#!/usr/bin/env bash
# Vérifie les sommes SHA256 et les signatures (Cosign, GPG) des binaires épinglés
# dans versions-outils.json, pour les deux architectures (linux/amd64 et linux/arm64).
# À lancer sur le poste d'administration après chaque changement de version, avant le
# playbook et avant une construction de l'image Docker.
# Prérequis : curl, jq, shasum ou sha256sum, cosign, gpg (macOS : brew install cosign gnupg jq)
set -euo pipefail

VERSIONS="$(cd "$(dirname "$0")/.." && pwd)/versions-outils.json"
[ -f "$VERSIONS" ] || { echo "versions-outils.json introuvable ($VERSIONS)"; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

if command -v sha256sum >/dev/null; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
for outil in cosign gpg jq; do
  command -v "$outil" >/dev/null || { echo "$outil absent (brew install cosign gnupg jq)"; exit 1; }
done

dl() { curl -fsSL -o "$2" "$1"; }
val() { jq -r "$1" "$VERSIONS"; }   # lecture d'une valeur de versions-outils.json

check_sha() { # fichier somme_attendue
  local got
  got=$($SHA "$1" | awk '{print $1}')
  if [ "$got" = "$2" ]; then echo "  SHA256 OK   $1"; else echo "  SHA256 FAUX $1 ($got)"; exit 1; fi
}

ISSUER=https://token.actions.githubusercontent.com
ARCHS="linux/amd64 linux/arm64"

V=$(val .binaires.trivy.version)
echo "== Trivy $V (fichier de sommes signé par Cosign)"
B=https://github.com/aquasecurity/trivy/releases/download/v$V
dl "$B/trivy_${V}_checksums.txt" trivy_sums.txt
dl "$B/trivy_${V}_checksums.txt.sigstore.json" trivy_sums.sigstore.json
cosign verify-blob trivy_sums.txt \
  --bundle trivy_sums.sigstore.json \
  --certificate-identity-regexp '^https://github.com/aquasecurity/trivy/\.github/workflows/' \
  --certificate-oidc-issuer "$ISSUER"
for a in $ARCHS; do
  url=$(val ".binaires.trivy[\"$a\"].url"); somme=$(val ".binaires.trivy[\"$a\"].sha256")
  dl "$url" "trivy-${a#linux/}.tgz"
  check_sha "trivy-${a#linux/}.tgz" "$somme"
  grep -q "^$somme  $(basename "$url")\$" trivy_sums.txt && echo "  Somme présente dans le fichier signé ($a)"
done

V=$(val .binaires.opengrep.version)
echo "== Opengrep $V (binaire signé par Cosign)"
for a in $ARCHS; do
  url=$(val ".binaires.opengrep[\"$a\"].url"); f="opengrep-${a#linux/}"
  dl "$url" "$f"; dl "$url.cert" "$f.cert"; dl "$url.sig" "$f.sig"
  cosign verify-blob "$f" \
    --certificate "$f.cert" \
    --signature "$f.sig" \
    --certificate-identity 'https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/main' \
    --certificate-oidc-issuer "$ISSUER"
  check_sha "$f" "$(val ".binaires.opengrep[\"$a\"].sha256")"
done

V=$(val .binaires.gitleaks.version)
echo "== Gitleaks $V (fichier de sommes, pas de signature vérifiée)"
dl "https://github.com/gitleaks/gitleaks/releases/download/v$V/gitleaks_${V}_checksums.txt" gitleaks_sums.txt
for a in $ARCHS; do
  url=$(val ".binaires.gitleaks[\"$a\"].url"); somme=$(val ".binaires.gitleaks[\"$a\"].sha256")
  dl "$url" "gitleaks-${a#linux/}.tgz"
  check_sha "gitleaks-${a#linux/}.tgz" "$somme"
  grep -q "^$somme  $(basename "$url")\$" gitleaks_sums.txt && echo "  Somme présente dans le fichier de sommes ($a)"
done

V=$(val '.binaires["osv-scanner"].version')
echo "== OSV-Scanner $V (fichier de sommes, pas de signature vérifiée)"
dl "https://github.com/google/osv-scanner/releases/download/v$V/osv-scanner_SHA256SUMS" osv_sums.txt
for a in $ARCHS; do
  url=$(val ".binaires[\"osv-scanner\"][\"$a\"].url"); somme=$(val ".binaires[\"osv-scanner\"][\"$a\"].sha256")
  dl "$url" "osv-scanner-${a#linux/}"
  check_sha "osv-scanner-${a#linux/}" "$somme"
  grep -q "^$somme  $(basename "$url")\$" osv_sums.txt && echo "  Somme présente dans le fichier de sommes ($a)"
done

# Psalm et PHPStan : PHAR signés GPG (indépendants de l'architecture). Empreintes des clés
# recoupées le 16/11/2026 :
# - Psalm : 99BF4D9A33D65E1E est écrite dans le script officiel vimeo/psalm bin/ci/build-phar.sh ;
# - PHPStan : 51C67305FFC2E5C0 est la clé du compte GitHub phpstan-bot, qui publie les versions.
# On exige que la signature soit faite par EXACTEMENT ces empreintes (pas de confiance au serveur de clés).
export GNUPGHOME="$TMP/gnupg"; mkdir -m 700 "$GNUPGHOME"
check_gpg() { # fichier empreinte_complète
  curl -fsSL "https://keys.openpgp.org/vks/v1/by-fingerprint/$2" | gpg --batch --quiet --import 2>/dev/null
  if gpg --batch --status-fd 1 --verify "$1.asc" "$1" 2>/dev/null | grep -q "^\[GNUPG:\] VALIDSIG .* $2\$\|^\[GNUPG:\] VALIDSIG $2 "; then
    echo "  GPG OK      $1 (clé $2)"
  else
    echo "  GPG FAUX    $1"; exit 1
  fi
}

echo "== Psalm $(val .binaires.psalm.version) (PHAR signé GPG)"
url=$(val .binaires.psalm.tous.url)
dl "$url" psalm.phar; dl "$url.asc" psalm.phar.asc
check_gpg psalm.phar 54F5DF0E979A94C40DEDE5E599BF4D9A33D65E1E
check_sha psalm.phar "$(val .binaires.psalm.tous.sha256)"

echo "== PHPStan $(val .binaires.phpstan.version) (PHAR signé GPG)"
url=$(val .binaires.phpstan.tous.url)
dl "$url" phpstan.phar; dl "$url.asc" phpstan.phar.asc
check_gpg phpstan.phar CA7C2C7A30C8E8E1274A847651C67305FFC2E5C0
check_sha phpstan.phar "$(val .binaires.phpstan.tous.sha256)"

echo "Tout est vérifié (linux/amd64 et linux/arm64)."
