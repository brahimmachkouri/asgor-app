#!/usr/bin/env bash
# Vérifie que chaque outil de l'image démarre et fonctionne, dans les conditions d'une
# étape « scan » : compte 10001, système en lecture seule, aucun réseau.
#   docker run --rm --user 10001:10001 --read-only --tmpfs /tmp --network none <image>
# Affiche une ligne par contrôle ; code de retour 1 si un contrôle échoue.
set -uo pipefail

export HOME=/tmp/home COMPOSER_HOME=/tmp/home/composer
mkdir -p "$HOME"
echecs=0

controle() { # libellé commande…
  local libelle=$1; shift
  local sortie
  if sortie=$(timeout 120 "$@" </dev/null 2>&1); then
    printf 'OK     %-28s %s\n' "$libelle" "$(printf '%s\n' "$sortie" | grep -m1 -v '^\s*$' | cut -c1-70)"
  else
    printf 'ÉCHEC  %-28s %s\n' "$libelle" "$(printf '%s\n' "$sortie" | tail -n 3 | tr '\n' ' ' | cut -c1-200)"
    echecs=$((echecs + 1))
  fi
}

echo "Architecture : $(uname -m) ; compte : $(id -u):$(id -g)"

# Versions (chaque binaire démarre sur cette architecture)
controle "gitleaks"          gitleaks version
controle "trivy"             trivy --version
controle "osv-scanner"       osv-scanner --version
controle "opengrep"          opengrep --version
controle "psalm"             psalm --version
controle "phpstan"           phpstan --version
controle "composer"          composer --version
controle "bandit"            bandit --version
controle "pip-audit"         pip-audit --version
controle "git"               git --version
controle "php"               php --version
controle "python3"           python3 --version

# Extensions PHP installées comme sur la VM
for extension in xml mbstring curl zip; do
  controle "extension PHP $extension" php -r "exit(extension_loaded('$extension') ? 0 : 1);"
done

# Petits essais réels, sans réseau
essai=/tmp/essai
mkdir -p "$essai/src"
cat > "$essai/src/app.py" <<'EOF'
import subprocess
def lancer(nom):
    subprocess.call("ls " + nom, shell=True)
EOF
cat > "$essai/src/index.php" <<'EOF'
<?php
echo $_GET['nom'];
EOF
printf 'aws_access_key_id = AKIAIOSFODNN7ASGORXX\n' > "$essai/src/config.ini"

controle "bandit (essai)"     bash -c "bandit -q -f json -o $essai/bandit.json --exit-zero $essai/src/app.py && grep -q B602 $essai/bandit.json"
controle "gitleaks (essai)"   bash -c "gitleaks dir $essai/src --no-banner --report-format json --report-path $essai/gitleaks.json --exit-code 0 && grep -q RuleID $essai/gitleaks.json"
controle "opengrep (essai)"   bash -c "opengrep scan --quiet --json-output=$essai/opengrep.json -l python -e 'subprocess.call(\$X, shell=True)' $essai/src && grep -q '\"check_id\"' $essai/opengrep.json"
controle "php (essai)"        php -l "$essai/src/index.php"
controle "git (essai)"        bash -c "cd $essai && git init -q depot && git -C depot config user.email a@b.c && git -C depot config user.name a && git -C depot commit -q --allow-empty -m essai"

if [ "$echecs" -eq 0 ]; then
  echo "Tous les contrôles sont OK."
else
  echo "$echecs contrôle(s) en échec."
  exit 1
fi
