"""File des demandes entre le service web et le worker.

Le service web (compte asgor-web) dépose un petit fichier par demande dans
/var/lib/asgor/file/. Le worker (root) relève le dossier, vérifie chaque
fichier champ par champ, puis le supprime. Le worker ne fait confiance à rien
de ce que contient ce dossier : un service web compromis pourrait y mettre
n'importe quoi.
"""

import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
import time
from dataclasses import dataclass

from . import fichiers
from .url import UrlInvalide, valider_url

FILE = "/var/lib/asgor/file"
# Demandes lisibles par le groupe : sur la VM, le dossier est en 0700 (asgor-web) et le
# worker est root ; dans l'image Docker, le worker (10001) est membre du groupe
# asgor-web (10002), propriétaire du dossier (2770).
MODE_DEMANDE = 0o640
TAILLE_MAX = 2048            # octets par fichier
NB_MAX_EN_FILE = 20          # demandes en attente acceptées par le service web
NB_MAX_PAR_RELEVE = 100      # fichiers traités par le worker à chaque passage
AGE_MAX_TEMPORAIRE = 60      # secondes : un .tmp plus vieux est abandonné

CHAMPS = ("id", "url", "historique_complet", "masquee", "forcee")
_ID = r"[0-9a-f]{32}"
_DEMANDE = re.compile(rf"({_ID})\.json")
_ANNULATION = re.compile(rf"({_ID})\.annuler")
_TEMPORAIRE = re.compile(rf"\.({_ID})\.tmp")
_MARQUAGE = re.compile(rf"({_ID})\.marquage")

# Marquage des faux positifs (BAREME.md § 6 c)
ECARTER = "ecarter"
RETABLIR = "retablir"
CHAMPS_MARQUAGE = ("id", "analyse", "action", "empreintes", "motif", "ip")
TAILLE_MAX_MARQUAGE = 16 * 1024
NB_MAX_EMPREINTES = 500
NB_MAX_MARQUAGES_EN_FILE = 50
MOTIF_MIN, MOTIF_MAX = 3, 300
_EMPREINTE = re.compile(r"[0-9a-f]{16}")


class FilePleine(Exception):
    """Trop de demandes en attente."""


@dataclass(frozen=True)
class Demande:
    id: str
    url: str                  # URL canonique reconstruite : https://github.com/<p>/<d>
    proprietaire: str
    nom: str
    historique_complet: bool
    masquee: bool
    forcee: bool


@dataclass(frozen=True)
class Marquage:
    id: str
    analyse: str
    action: str               # ECARTER ou RETABLIR
    empreintes: tuple         # identifiants de problèmes (16 hex), sans doublon
    motif: str
    ip: str


class MarquageInvalide(ValueError):
    """Demande de marquage refusée (raison courte, affichable)."""


def _verifier_marquage(analyse, action, empreintes, motif, ip) -> tuple:
    """Contrôles communs au service web et au worker. Renvoie (empreintes, motif, ip)."""
    if not isinstance(analyse, str) or not re.fullmatch(_ID, analyse):
        raise MarquageInvalide("identifiant d'analyse invalide")
    if action not in (ECARTER, RETABLIR):
        raise MarquageInvalide("action inconnue")
    if not isinstance(empreintes, (list, tuple)) or not empreintes:
        raise MarquageInvalide("aucun résultat sélectionné")
    if len(empreintes) > NB_MAX_EMPREINTES:
        raise MarquageInvalide(f"{NB_MAX_EMPREINTES} résultats au plus à la fois")
    if any(not isinstance(e, str) or not _EMPREINTE.fullmatch(e) for e in empreintes):
        raise MarquageInvalide("identifiant de résultat invalide")
    if not isinstance(motif, str):
        raise MarquageInvalide("motif invalide")
    motif = " ".join(motif.split())          # pas de saut de ligne ni de caractère de contrôle
    motif = "".join(c for c in motif if c.isprintable())
    if action == ECARTER and len(motif) < MOTIF_MIN:
        raise MarquageInvalide("motif obligatoire (3 caractères au moins)")
    if len(motif) > MOTIF_MAX:
        raise MarquageInvalide(f"motif trop long ({MOTIF_MAX} caractères au plus)")
    try:
        ip = str(ipaddress.ip_address(ip)) if ip else ""
    except ValueError:
        raise MarquageInvalide("adresse IP invalide") from None
    return tuple(dict.fromkeys(empreintes)), motif, ip


# ------------------------------------------------------------ côté service web

def deposer_marquage(analyse: str, action: str, empreintes, motif: str, ip: str,
                     dossier: str = FILE) -> str:
    """Dépose une demande d'écart (ou de rétablissement) de résultats.
    Lève MarquageInvalide ou FilePleine."""
    empreintes, motif, ip = _verifier_marquage(analyse, action, list(empreintes), motif, ip)
    try:
        en_file = sum(1 for e in os.scandir(dossier) if _MARQUAGE.fullmatch(e.name))
    except FileNotFoundError:
        en_file = 0
    if en_file >= NB_MAX_MARQUAGES_EN_FILE:
        raise FilePleine("trop de demandes en attente")
    identifiant = secrets.token_hex(16)
    contenu = json.dumps({"id": identifiant, "analyse": analyse, "action": action,
                          "empreintes": list(empreintes), "motif": motif, "ip": ip},
                         ensure_ascii=False)
    temporaire = os.path.join(dossier, f".{identifiant}.tmp")
    fichiers.ecrire_nouveau(temporaire, contenu, MODE_DEMANDE)
    os.rename(temporaire, os.path.join(dossier, f"{identifiant}.marquage"))
    return identifiant


def deposer_demande(url: str, historique_complet: bool = True, masquee: bool = False,
                    forcee: bool = False, dossier: str = FILE) -> str:
    """Valide l'URL et dépose la demande. Renvoie l'identifiant (32 hex).

    Lève UrlInvalide ou FilePleine.
    """
    depot = valider_url(url)
    if nb_en_file(dossier) >= NB_MAX_EN_FILE:
        raise FilePleine("trop d'analyses en attente")
    identifiant = secrets.token_hex(16)
    contenu = json.dumps({
        "id": identifiant,
        "url": f"https://github.com/{depot.proprietaire}/{depot.nom}",
        "historique_complet": bool(historique_complet),
        "masquee": bool(masquee),
        "forcee": bool(forcee),
    })
    temporaire = os.path.join(dossier, f".{identifiant}.tmp")
    fichiers.ecrire_nouveau(temporaire, contenu, MODE_DEMANDE)
    # Le renommage est atomique : le worker ne voit jamais un fichier à moitié écrit.
    os.rename(temporaire, os.path.join(dossier, f"{identifiant}.json"))
    return identifiant


def deposer_annulation(identifiant: str, dossier: str = FILE) -> None:
    if not isinstance(identifiant, str) or not re.fullmatch(_ID, identifiant):
        raise ValueError("identifiant invalide")
    try:
        fichiers.ecrire_nouveau(os.path.join(dossier, f"{identifiant}.annuler"), "", MODE_DEMANDE)
    except FileExistsError:
        pass  # déjà demandée


def nb_en_file(dossier: str = FILE) -> int:
    try:
        return sum(1 for e in os.scandir(dossier) if _DEMANDE.fullmatch(e.name))
    except FileNotFoundError:
        return 0


def demande_en_file(identifiant: str, dossier: str = FILE) -> bool:
    """Vrai si la demande est déposée mais pas encore relevée par le worker."""
    if not isinstance(identifiant, str) or not re.fullmatch(_ID, identifiant):
        return False
    return os.path.lexists(os.path.join(dossier, f"{identifiant}.json"))


# ------------------------------------------------------------------ côté worker

def _supprimer(chemin: str) -> None:
    try:
        infos = os.lstat(chemin)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(infos.st_mode):
        shutil.rmtree(chemin, ignore_errors=True)  # ne suit pas les liens symboliques
    else:
        try:
            os.unlink(chemin)
        except FileNotFoundError:
            pass


def _nom_affichable(nom: str) -> str:
    """Nom de fichier pour le journal du worker : jamais le contenu, nom tronqué."""
    return repr(nom[:80])


def _lire_demande(chemin: str, identifiant: str) -> Demande:
    """Lève ValueError avec une raison courte si le fichier est refusé."""
    try:
        brut = fichiers.lire_octets(chemin, TAILLE_MAX)
    except fichiers.LectureRefusee as e:
        raise ValueError(str(e).rsplit(" : ", 1)[-1]) from None
    try:
        donnees = json.loads(brut.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("JSON invalide") from None
    if not isinstance(donnees, dict) or set(donnees) != set(CHAMPS):
        raise ValueError("champs inattendus")
    if donnees["id"] != identifiant:
        raise ValueError("identifiant différent du nom du fichier")
    for champ in ("historique_complet", "masquee", "forcee"):
        if not isinstance(donnees[champ], bool):
            raise ValueError(f"{champ} n'est pas un booléen")
    try:
        depot = valider_url(donnees["url"])
    except UrlInvalide:
        raise ValueError("URL refusée") from None
    return Demande(
        id=identifiant,
        url=f"https://github.com/{depot.proprietaire}/{depot.nom}",
        proprietaire=depot.proprietaire,
        nom=depot.nom,
        historique_complet=donnees["historique_complet"],
        masquee=donnees["masquee"],
        forcee=donnees["forcee"],
    )


def _lire_marquage(chemin: str, identifiant: str) -> Marquage:
    try:
        brut = fichiers.lire_octets(chemin, TAILLE_MAX_MARQUAGE)
    except fichiers.LectureRefusee as e:
        raise ValueError(str(e).rsplit(" : ", 1)[-1]) from None
    try:
        donnees = json.loads(brut.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("JSON invalide") from None
    if not isinstance(donnees, dict) or set(donnees) != set(CHAMPS_MARQUAGE):
        raise ValueError("champs inattendus")
    if donnees["id"] != identifiant:
        raise ValueError("identifiant différent du nom du fichier")
    empreintes, motif, ip = _verifier_marquage(donnees["analyse"], donnees["action"],
                                               donnees["empreintes"], donnees["motif"], donnees["ip"])
    return Marquage(id=identifiant, analyse=donnees["analyse"], action=donnees["action"],
                    empreintes=empreintes, motif=motif, ip=ip)


def relever(dossier: str = FILE, maintenant: float | None = None, marquages: list | None = None):
    """Relève la file. Renvoie (demandes, annulations, rejets).
    Les demandes de marquage sont ajoutées à la liste « marquages » si elle est
    fournie (worker) ; sinon elles sont refusées.

    - demandes : liste de Demande, de la plus ancienne à la plus récente ;
    - annulations : liste d'identifiants ;
    - rejets : phrases courtes pour le journal du worker (sans le contenu des fichiers).

    Chaque fichier traité est supprimé, accepté ou non.
    """
    maintenant = time.time() if maintenant is None else maintenant
    demandes, annulations, rejets = [], [], []
    try:
        entrees = list(os.scandir(dossier))
    except FileNotFoundError:
        return demandes, annulations, rejets

    lus = []
    for entree in entrees:
        try:
            infos = entree.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        lus.append((infos.st_mtime_ns, entree.name, infos))
    lus.sort()

    for _date, nom, infos in lus[:NB_MAX_PAR_RELEVE]:
        chemin = os.path.join(dossier, nom)
        if _TEMPORAIRE.fullmatch(nom):
            # En cours d'écriture par le service web : on le laisse, sauf s'il est abandonné.
            if maintenant - infos.st_mtime > AGE_MAX_TEMPORAIRE:
                _supprimer(chemin)
                rejets.append(f"fichier temporaire abandonné supprimé : {_nom_affichable(nom)}")
            continue
        m_demande = _DEMANDE.fullmatch(nom)
        m_annulation = _ANNULATION.fullmatch(nom)
        m_marquage = _MARQUAGE.fullmatch(nom)
        try:
            if not stat.S_ISREG(infos.st_mode):
                raise ValueError("ce n'est pas un fichier ordinaire")
            if infos.st_nlink != 1:
                # Lien physique vers un autre fichier : refusé (défense en plus de
                # fs.protected_hardlinks et du disque de données séparé).
                raise ValueError("fichier avec plusieurs liens physiques")
            if m_demande:
                demandes.append(_lire_demande(chemin, m_demande.group(1)))
            elif m_annulation:
                if infos.st_size != 0:
                    raise ValueError("une annulation doit être vide")
                annulations.append(m_annulation.group(1))
            elif m_marquage and marquages is not None:
                marquages.append(_lire_marquage(chemin, m_marquage.group(1)))
            else:
                raise ValueError("nom de fichier inattendu")
        except ValueError as e:
            rejets.append(f"fichier refusé {_nom_affichable(nom)} : {e}")
        finally:
            _supprimer(chemin)
    return demandes, annulations, rejets
