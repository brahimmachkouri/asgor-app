"""Résultats écartés comme faux positifs (BAREME.md § 6 c).

Le worker marque les problèmes écartés dans le rapport (« ecarte »), recalcule la
note sans eux et réécrit le rapport et l'export SARIF. Le motif, la date et
l'adresse IP restent dans la base : ils ne vont pas dans les exports.
"""

import dataclasses
import grp
import json
import os

from . import fichiers, sarif
from .modele import DOMAINES, Probleme
from .notation import Contexte, noter

GROUPE_WEB = "asgor-web"
_CHAMPS = {f.name for f in dataclasses.fields(Probleme)}
_PREFIXE_VERROUILLAGE = "analyse des dépendances incomplète : "


def contexte_depuis_rapport(rapport: dict) -> Contexte:
    """Ce que la note sait en plus des problèmes, relu dans le rapport."""
    note = rapport.get("note", {})
    echecs = {d: list(note.get("domaines", {}).get(d, {}).get("outils_en_echec", []))
              for d in DOMAINES}
    sans_verrouillage = [p["raison"][len(_PREFIXE_VERROUILLAGE):]
                         for p in note.get("tous_les_plafonnements", [])
                         if isinstance(p.get("raison"), str)
                         and p["raison"].startswith(_PREFIXE_VERROUILLAGE)]
    historique = rapport.get("analyse", {}).get("historique_complet", True)
    return Contexte(outils_en_echec={d: e for d, e in echecs.items() if e},
                    sans_verrouillage=sans_verrouillage,
                    historique_non_analyse=not historique)


def _probleme(d: dict) -> Probleme:
    return Probleme(**{k: v for k, v in d.items() if k in _CHAMPS})


def appliquer(rapport: dict, ecartes) -> bool:
    """Marque les problèmes écartés et recalcule la note. Vrai si le rapport a changé."""
    ecartes = set(ecartes)
    change = False
    for p in rapport.get("problemes", []):
        voulu = p.get("id") in ecartes
        if bool(p.get("ecarte")) != voulu:
            change = True
        if voulu:
            p["ecarte"] = True
        else:
            p.pop("ecarte", None)
    if change:
        rapport["note"] = noter([_probleme(p) for p in rapport.get("problemes", [])],
                                contexte_depuis_rapport(rapport))
    return change


def _ecrire_remplacer(chemin: str, texte: str, gid) -> None:
    temporaire = os.path.join(os.path.dirname(chemin), "." + os.path.basename(chemin) + ".tmp")
    fichiers.supprimer(temporaire)
    fichiers.ecrire_nouveau(temporaire, texte, 0o600)
    if gid is not None:
        os.chown(temporaire, 0, gid)
        os.chmod(temporaire, 0o640)
    os.replace(temporaire, chemin)     # atomique : le service web ne lit jamais un fichier à moitié écrit


def reecrire(dossier_rapports: str, identifiant: str, rapport: dict) -> None:
    """Réécrit <id>.json et <id>.sarif (mêmes droits que ceux écrits par le moteur)."""
    try:
        gid = grp.getgrnam(GROUPE_WEB).gr_gid
    except KeyError:
        gid = None
    base_chemin = os.path.join(dossier_rapports, identifiant)
    _ecrire_remplacer(base_chemin + ".json", json.dumps(rapport, ensure_ascii=False, indent=2) + "\n", gid)
    _ecrire_remplacer(base_chemin + ".sarif",
                      json.dumps(sarif.vers_sarif(rapport), ensure_ascii=False, indent=2) + "\n", gid)
