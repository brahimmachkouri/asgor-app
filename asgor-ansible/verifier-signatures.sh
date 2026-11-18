#!/usr/bin/env bash
# Vérifie les sommes SHA256 et les signatures Cosign des binaires épinglés
# dans asgor.yml. À lancer sur le poste d'administration, avant le playbook.
# Prérequis : curl, shasum ou sha256sum, cosign (macOS : brew install cosign)
set -euo pipefail

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

if command -v sha256sum >/dev/null; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
command -v cosign >/dev/null || { echo "cosign absent (brew install cosign)"; exit 1; }

dl() { curl -fsSL -o "$2" "$1"; }

check_sha() { # fichier somme_attendue
  local got
  got=$($SHA "$1" | awk '{print $1}')
  if [ "$got" = "$2" ]; then echo "  SHA256 OK   $1"; else echo "  SHA256 FAUX $1 ($got)"; exit 1; fi
}

GH=https://github.com
ISSUER=https://token.actions.githubusercontent.com

echo "== Trivy 0.76.2"
B=$GH/aquasecurity/trivy/releases/download/v0.76.2
dl $B/trivy_0.76.2_Linux-64bit.tar.gz trivy.tgz
dl $B/trivy_0.76.2_checksums.txt trivy_sums.txt
dl $B/trivy_0.76.2_checksums.txt.sigstore.json trivy_sums.sigstore.json
cosign verify-blob trivy_sums.txt \
  --bundle trivy_sums.sigstore.json \
  --certificate-identity-regexp '^https://github.com/aquasecurity/trivy/\.github/workflows/' \
  --certificate-oidc-issuer "$ISSUER"
check_sha trivy.tgz bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
grep -q 'bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf  trivy_0.76.2_Linux-64bit.tar.gz' trivy_sums.txt \
  && echo "  Somme présente dans le fichier signé"

echo "== Opengrep 2.0.0"
B=$GH/opengrep/opengrep/releases/download/v2.0.0
dl $B/opengrep_linux_x86 opengrep
dl $B/opengrep_linux_x86.cert opengrep.cert
dl $B/opengrep_linux_x86.sig opengrep.sig
cosign verify-blob opengrep \
  --certificate opengrep.cert \
  --signature opengrep.sig \
  --certificate-identity 'https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/main' \
  --certificate-oidc-issuer "$ISSUER"
check_sha opengrep 37e93f4da5fd04a18c5c1febbdd12f7e98dfccd4d0c9cf2593bcb25eeb462da0

echo "== Gitleaks 8.30.1 (fichier de sommes, pas de signature vérifiée)"
B=$GH/gitleaks/gitleaks/releases/download/v8.30.1
dl $B/gitleaks_8.30.1_linux_x64.tar.gz gitleaks.tgz
check_sha gitleaks.tgz 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

echo "== OSV-Scanner 2.7.1 (fichier de sommes, pas de signature vérifiée)"
B=$GH/google/osv-scanner/releases/download/v2.7.1
dl $B/osv-scanner_linux_amd64 osv-scanner
check_sha osv-scanner fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8

# Psalm et PHPStan : PHAR signés GPG. Empreintes des clés recoupées le 16/11/2026 :
# - Psalm : 99BF4D9A33D65E1E est écrite dans le script officiel vimeo/psalm bin/ci/build-phar.sh ;
# - PHPStan : 51C67305FFC2E5C0 est la clé du compte GitHub phpstan-bot, qui publie les versions.
# On exige que la signature soit faite par EXACTEMENT ces empreintes (pas de confiance au serveur de clés).
command -v gpg >/dev/null || { echo "gpg absent (brew install gnupg)"; exit 1; }
export GNUPGHOME="$TMP/gnupg"; mkdir -m 700 "$GNUPGHOME"
check_gpg() { # fichier empreinte_complète
  curl -fsSL "https://keys.openpgp.org/vks/v1/by-fingerprint/$2" | gpg --batch --quiet --import 2>/dev/null
  if gpg --batch --status-fd 1 --verify "$1.asc" "$1" 2>/dev/null | grep -q "^\[GNUPG:\] VALIDSIG .* $2\$\|^\[GNUPG:\] VALIDSIG $2 "; then
    echo "  GPG OK      $1 (clé $2)"
  else
    echo "  GPG FAUX    $1"; exit 1
  fi
}

echo "== Psalm 7.5.0 (PHAR signé GPG)"
B=$GH/vimeo/psalm/releases/download/7.5.0
dl $B/psalm.phar psalm.phar
dl $B/psalm.phar.asc psalm.phar.asc
check_gpg psalm.phar 54F5DF0E979A94C40DEDE5E599BF4D9A33D65E1E
check_sha psalm.phar cdb2430a6cfaff77863e0d965dc6d2c5b03a9351460d4c4b5e587ed701be41a7

echo "== PHPStan 2.3.4 (PHAR signé GPG)"
B=$GH/phpstan/phpstan/releases/download/2.3.4
dl $B/phpstan.phar phpstan.phar
dl $B/phpstan.phar.asc phpstan.phar.asc
check_gpg phpstan.phar CA7C2C7A30C8E8E1274A847651C67305FFC2E5C0
check_sha phpstan.phar a961d12cc71941a31ad6560e6a330347d487612628c3202a718f71a59de21a7c

echo "Tout est vérifié."
