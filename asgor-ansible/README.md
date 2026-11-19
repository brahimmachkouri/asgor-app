# ASGOR — playbook de la VM (Ubuntu Server 26.04 LTS)

Ce playbook installe tout ASGOR sur la VM : socle, outils épinglés, isolation des analyses, moteur, worker, service web et services systemd.

## Préparation de la VM

- VM QEMU/KVM Proxmox, ISO Ubuntu Server 26.04 LTS, 4 vCPU, 8 Go RAM, q35 + OVMF.
- Deux disques : système (32 Go) et **données (50 Go), monté sur `/mnt/data`** (entrée dans `/etc/fstab`). Le playbook s'arrête si `/mnt/data` n'est pas monté.
- Option « QEMU Guest Agent » activée dans Proxmox.
- Installer OpenSSH Server et ajouter la clé SSH du poste Ansible dans `/root/.ssh/authorized_keys` (Ansible se connecte en root).
- Pare-feu Proxmox : n'autoriser que les IP d'administration en entrée.
- Sorties HTTPS nécessaires : archive Ubuntu, PyPI, Packagist, GitHub (releases, clones, API publique), `mirror.gcr.io` et `ghcr.io` (bases Trivy), base OSV (Google).

## Versions épinglées

Règle : versions exactes, avec SHA256, **publiées depuis au moins 14 jours**.

| Outil | Version | Origine du SHA256 |
|---|---|---|
| Bandit | 1.9.4 | PyPI |
| pip-audit | 2.10.1 | PyPI |
| Psalm | 7.5.0 | PHAR GitHub, SHA256 + signature GPG (exception à la règle des 14 jours jusqu'au 28/11/2026) |
| PHPStan | 2.3.4 | PHAR GitHub, SHA256 + signature GPG |
| Gitleaks | 8.30.1 | fichier de sommes de la release |
| Trivy | 0.76.2 | fichier de sommes de la release, signé (Cosign) |
| OSV-Scanner | 2.7.1 | fichier de sommes de la release |
| Opengrep | 2.0.0 | calculé sur le binaire ; binaire signé (Cosign) |
| Règles Semgrep | commit `a5ad171` | archive GitHub (jamais copiées dans le dépôt : licence) |
| Service web | `web/requirements.txt` | API JSON de PyPI, une somme par fichier publié |

Psalm et PHPStan sont installés sous forme de PHAR (un seul fichier chacun, SHA256 dans `../versions-outils.json`, signature GPG vérifiée par `verifier-signatures.sh`). Avant, Composer installait 55 paquets sans aucune somme de contrôle (Packagist n'en publie pas).

## Adresses du réseau d'installation

Les adresses propres à votre réseau sont dans deux fichiers **hors Git**, à créer à partir des exemples :

```bash
cp inventory.ini.exemple inventory.ini   # adresse de la VM
cp reseau.yml.exemple reseau.yml         # asgor_admin_ips, asgor_proxy_ips
```

- `asgor_admin_ips` : IP autorisées par UFW pour SSH. Le playbook refuse de continuer si vous n'êtes pas connecté depuis l'une d'elles.
- `asgor_proxy_ips` : adresse du reverse proxy, telle que la VM la voit. Seule cette adresse peut joindre le port 8000.

Sans `reseau.yml`, le playbook s'arrête dès le début.

## Étape 0 : vérifier les signatures sur le poste d'administration

```bash
brew install cosign gnupg   # une seule fois
./verifier-signatures.sh
```

Le script doit se terminer par « Tout est vérifié. ». Sinon, ne pas lancer le playbook.

**Trivy** : la chaîne de publication de Trivy a été compromise en mars 2026 (CVE-2026-33634, version 0.69.4 malveillante). C'est pour cela qu'il est installé par un binaire épinglé et vérifié, et non par le dépôt APT d'Aqua mis à jour automatiquement.

## Exécution depuis le poste Ansible

```bash
ansible-galaxy collection install -r requirements.yml
ansible -i inventory.ini asgor -m ping
ansible-playbook -i inventory.ini asgor.yml --check --diff
ansible-playbook -i inventory.ini asgor.yml
```

Règle : si seul le code (`moteur/`, `web/`) a changé, lancement réel directement ; si le playbook ou `files/` ont changé, simulation `--check --diff` d'abord.

En simulation, quelques erreurs sont normales sur une VM qui n'a pas encore reçu une partie : groupe `asgor-web` absent, services inconnus, dossier de règles absent.

## Mettre à jour un outil plus tard

1. Changer la version et les sommes (une par architecture) dans `../versions-outils.json`, seule source lue par le playbook et par le Dockerfile (somme prise dans le fichier de sommes de la release).
2. Relancer `verifier-signatures.sh` (il lit `versions-outils.json` et vérifie les deux architectures).
3. Relancer le playbook. L'ancienne version reste dans `/opt/asgor/tools/<outil>/` pour un retour arrière.

## Ce que fait le playbook

- **Socle** : paquets, QEMU Guest Agent, comptes `asgor` (analyses) et `asgor-web` (service web), sans shell.
- **Disque de données** : `/var/lib/asgor` est un montage « bind » de `/mnt/data/asgor`. Aucune donnée ne va sur le disque système.
- **Dossiers** : `/var/lib/asgor` en 0751 (traversable, pas listable) ; `jobs`, `cache`, `logs`, `.ssh` en 0700 pour `asgor` ; `database` et `reports` en `root:asgor-web` 0750 ; `file` en `asgor-web` 0700.
- **Mises à jour** : unattended-upgrades limité **réellement** aux origines de sécurité (`#clear` sur les listes par défaut), avec un contrôle automatique ; redémarrage seulement si nécessaire, le samedi à 23 h (`asgor-reboot.timer`).
- **SSH et UFW** : clé uniquement ; root autorisé par clé (Ansible l'utilise) ; le playbook vérifie qu'une clé est installée avant de couper les mots de passe. UFW refuse tout sauf les IP d'administration.
- **Outils** : Python dans un venv chacun ; PHP par Composer, sans plugins ni scripts ; binaires dans `/opt/asgor/tools/<outil>/<version>/` avec lien dans `/usr/local/bin`. `/opt/asgor/outils.json` donne les versions affichées par l'application.
- **Isolation** : `asgor-sandbox` et son autotest (30 contrôles) ; le playbook s'arrête si un contrôle échoue.
- **Règles Semgrep/Opengrep** : téléchargées à un commit figé avec contrôle SHA256 dans `/opt/asgor/regles/semgrep-rules/`.
- **Moteur et worker** : copie de `moteur/` dans `/opt/asgor/moteur` ; commandes `asgor-scan` et `asgor-worker`.
- **Service web** : copie de `web/asgor_web/` dans `/opt/asgor/web` ; environnement `/opt/asgor/venvs/web` installé avec `--require-hashes`, puis `pip check` ; commande `asgor-web`.
- **Services systemd** `asgor-worker` et `asgor-web`, durcis et activés au démarrage. Le playbook les redémarre quand le code change (une analyse en cours est alors arrêtée et marquée en échec).

## Vérifications sur la VM

```bash
systemctl status asgor-worker asgor-web
journalctl -u asgor-worker -u asgor-web -n 50
curl -s http://127.0.0.1:8000/sante                # « ok » si la base est lisible et le worker vivant
systemd-analyze security asgor-web               # 1,1 (OK) au 15/11/2026
sudo /usr/local/sbin/asgor-sandbox-selftest      # « Isolation : tous les contrôles sont OK. »
cat /opt/asgor/outils.json
findmnt /var/lib/asgor                           # /dev/sdb1[/asgor]
sudo ufw status verbose
```

Analyse en ligne de commande (sans l'application web) :

```bash
sudo asgor-scan https://github.com/digininja/DVWA
sudo asgor-scan --sans-historique https://github.com/digininja/DVWA
```

## Isolation des analyses

Chaque étape d'une analyse passe par `/usr/local/sbin/asgor-sandbox`, qui la lance dans une unité systemd temporaire :

| | Profil `fetch` | Profil `scan` |
|---|---|---|
| Usage | `git ls-remote`, `git clone`, `composer install`, Composer Audit, pip-audit, bases Trivy/OSV | Gitleaks, OSV-Scanner et Trivy hors ligne, Psalm, PHPStan, Opengrep, Bandit |
| Réseau | Internet seulement (réseau interne et VM interdits) | aucun |
| Cache `/var/lib/asgor/cache` | lecture/écriture | lecture seule |

Dans les deux profils :
- compte `asgor`, aucune capacité, pas d'élévation de droits ;
- système en lecture seule ; seul `/var/lib/asgor/jobs/<id>` est accessible en écriture ;
- les autres analyses, la base, les rapports, les clés SSH, `/root`, `/etc/ssh` et `/mnt/data` sont invisibles ;
- limites de mémoire (4 Go, 6 Go pour Psalm), de CPU et de durée (`/etc/asgor/sandbox.conf`) ;
- git n'accepte que `https://`.

Règle pour le moteur : **ne jamais utiliser les fichiers de configuration du dépôt analysé** (`psalm.xml`, `phpstan.neon`, `.gitleaks.toml`, `trivy.yaml`…) et **ne jamais exécuter son code**. Options passées à chaque outil : `README.md`, « Options des outils ».

Si l'université impose un proxy HTTP interne pour sortir sur Internet, ajouter son adresse à `asgor_sandbox_allow_cidrs`.

## Accès par le reverse proxy Caddy

- Caddy (`asgor_proxy_ips`, dans `reseau.yml`) gère le certificat et filtre les IP d'administration. Pas de Nginx sur la VM.
- Le service web écoute sur le port `asgor_web_port` (8000). UFW n'ouvre ce port qu'à Caddy, et le service systemd n'accepte que la VM et Caddy (`IPAddressAllow`).
- `asgor-web --proxy <IP de Caddy>` : les en-têtes `X-Forwarded-For` et `X-Forwarded-Proto` ne sont acceptés que de Caddy. En HTTPS, le cookie CSRF est `Secure` et l'en-tête HSTS est envoyé.
- Côté Caddy : rediriger vers `<adresse de la VM>:8000`, filtrer les IP d'administration, et **ne pas utiliser `upstream_host`** (le contrôle d'origine des formulaires a besoin du nom d'hôte d'origine).

## Pas encore fait

- Sauvegarde de `/var/lib/asgor/database` et `/var/lib/asgor/reports`.
