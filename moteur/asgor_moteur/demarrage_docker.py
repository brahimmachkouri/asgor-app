"""Démarrage du worker dans l'image Docker.

Remplace les contrôles de la VM (« être root », « données sur le disque de données ») :

1. le filtre du socket Docker répond ;
2. les dossiers des volumes existent et sont utilisables par le worker ;
3. la clé d'empreinte des secrets existe (créée au premier démarrage, 32 octets, 0600) ;
4. les règles Semgrep sont installées au commit de l'image (sinon : installation,
   par une étape lancée par le filtre).
"""

import json
import os
import secrets
import time

from . import moteur as module_moteur
from .etapes import FiltreInjoignable, demander_filtre

TAILLE_CLE = 32
VERSIONS = "/opt/asgor/versions-outils.json"
DOSSIER_REGLES = "/opt/asgor/regles/semgrep-rules"
DUREE_MAX_REGLES = 600


class DemarrageImpossible(Exception):
    pass


def journal(message: str) -> None:
    print(f"asgor-worker : {message}", flush=True)


def creer_cle(chemin: str) -> None:
    """Crée la clé d'empreinte si elle manque ; jamais remplacée ensuite."""
    os.makedirs(os.path.dirname(chemin), mode=0o700, exist_ok=True)
    try:
        fd = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(TAILLE_CLE))
        journal(f"clé d'empreinte des secrets créée ({chemin})")
    infos = os.lstat(chemin)
    if not os.path.isfile(chemin) or os.path.islink(chemin) or infos.st_size < TAILLE_CLE:
        raise DemarrageImpossible(f"clé d'empreinte des secrets invalide : {chemin}")
    if infos.st_mode & 0o077:
        os.chmod(chemin, 0o600)


def verifier_dossiers() -> None:
    for dossier in (module_moteur.ANALYSES, module_moteur.RAPPORTS, module_moteur.JOURNAUX,
                    os.path.dirname(module_moteur.CACHE_OSV)):
        os.makedirs(dossier, mode=0o750, exist_ok=True)
        if not os.access(dossier, os.W_OK | os.X_OK):
            raise DemarrageImpossible(f"dossier sans droit d'écriture pour le worker : {dossier}")


def installer_regles(versions: str = VERSIONS, dossier: str = DOSSIER_REGLES) -> None:
    with open(versions, encoding="utf-8") as f:
        commit = json.load(f)["regles_semgrep"]["commit"]
    actuel = os.path.join(dossier, "actuel")
    if os.path.realpath(actuel) == os.path.realpath(os.path.join(dossier, commit)) \
            and os.path.isfile(os.path.join(actuel, "LICENSE")):
        return
    journal(f"installation des règles Semgrep {commit[:7]} (première fois ou nouvelle version)")
    reponse, _ = demander_filtre({"action": "regles"})
    conteneur = reponse["conteneur"]
    try:
        limite = time.monotonic() + DUREE_MAX_REGLES
        while True:
            etat, _ = demander_filtre({"action": "attendre", "conteneur": conteneur})
            if etat["termine"]:
                break
            if time.monotonic() > limite:
                demander_filtre({"action": "tuer", "conteneur": conteneur})
                raise DemarrageImpossible("installation des règles Semgrep : délai dépassé")
            time.sleep(1)
        _, texte = demander_filtre({"action": "journaux", "conteneur": conteneur})
    finally:
        demander_filtre({"action": "supprimer", "conteneur": conteneur})
    if etat["code"] != 0 or not os.path.isfile(os.path.join(actuel, "LICENSE")):
        raise DemarrageImpossible("installation des règles Semgrep en échec : "
                                  + texte.decode("utf-8", "replace").strip()[-500:])
    journal(texte.decode("utf-8", "replace").strip()[-200:])


def preparer(cle: str) -> None:
    try:
        version, _ = demander_filtre({"action": "version"})
    except FiltreInjoignable as e:
        raise DemarrageImpossible(str(e)) from None
    journal(f"filtre prêt (Docker {version.get('docker')}, image {str(version.get('image'))[:19]}…)")
    verifier_dossiers()
    creer_cle(cle)
    try:
        installer_regles()
    except FiltreInjoignable as e:
        raise DemarrageImpossible(f"installation des règles Semgrep : {e}") from None
