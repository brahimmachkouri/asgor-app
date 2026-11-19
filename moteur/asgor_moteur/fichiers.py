"""Lecture et écriture prudentes dans le dossier d'une analyse.

Le moteur tourne en root. Le dossier de l'analyse appartient au compte
asgor et contient des fichiers venus du dépôt analysé ou écrits par les
outils. On ne suit donc jamais un lien symbolique et on limite la taille lue.
"""

import json
import os
import shutil
import stat

TAILLE_MAX_JSON = 300 * 1024 * 1024
TAILLE_MAX_TEXTE = 5 * 1024 * 1024


class LectureRefusee(Exception):
    pass


def lire_octets(chemin: str, taille_max: int) -> bytes:
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        raise LectureRefusee(f"{chemin} : {e.strerror}") from e
    try:
        infos = os.fstat(fd)
        if not stat.S_ISREG(infos.st_mode):
            raise LectureRefusee(f"{chemin} : ce n'est pas un fichier ordinaire")
        if infos.st_size > taille_max:
            raise LectureRefusee(f"{chemin} : fichier trop gros ({infos.st_size} octets)")
        morceaux = []
        restant = taille_max + 1
        while restant > 0:
            bloc = os.read(fd, min(restant, 1024 * 1024))
            if not bloc:
                break
            morceaux.append(bloc)
            restant -= len(bloc)
        donnees = b"".join(morceaux)
        if len(donnees) > taille_max:
            raise LectureRefusee(f"{chemin} : fichier trop gros")
        return donnees
    finally:
        os.close(fd)


def lire_texte(chemin: str, taille_max: int = TAILLE_MAX_TEXTE) -> str:
    return lire_octets(chemin, taille_max).decode("utf-8", "replace")


def lire_json(chemin: str, taille_max: int = TAILLE_MAX_JSON):
    donnees = lire_octets(chemin, taille_max)
    try:
        return json.loads(donnees.decode("utf-8", "replace"))
    except ValueError as e:
        raise LectureRefusee(f"{chemin} : JSON invalide ({e})") from e


def ecrire_nouveau(chemin: str, contenu: str, mode: int = 0o644) -> None:
    """Crée un fichier. Échoue s'il existe déjà ou si c'est un lien."""
    fd = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(contenu)


def supprimer(chemin: str) -> None:
    """Supprime un fichier (ou un lien, sans le suivre). Sans erreur s'il manque."""
    try:
        os.unlink(chemin)
    except FileNotFoundError:
        pass


def supprimer_arbre(chemin: str) -> None:
    """Supprime un dossier et son contenu, sans suivre les liens, même si un outil y a
    laissé un dossier sans droit d'écriture (même compte : on rétablit le droit)."""
    def reessayer(fonction, chemin_erreur, _exc):
        try:
            os.chmod(os.path.dirname(chemin_erreur), 0o700)
            if os.path.isdir(chemin_erreur) and not os.path.islink(chemin_erreur):
                os.chmod(chemin_erreur, 0o700)
            fonction(chemin_erreur)
        except OSError:
            pass
    if os.path.lexists(chemin):
        shutil.rmtree(chemin, onexc=reessayer)


def taille_dossier(racine: str, plafond: int) -> int:
    """Somme des tailles des fichiers, sans suivre les liens.

    S'arrête dès que le plafond est dépassé.
    """
    total = 0
    for dossier, _sous_dossiers, fichiers in os.walk(racine, followlinks=False):
        for nom in fichiers:
            try:
                total += os.lstat(os.path.join(dossier, nom)).st_size
            except OSError:
                continue
            if total > plafond:
                return total
    return total
