"""Mise en forme pour les pages : dates, durées, classes CSS.

Les couleurs et les largeurs passent par des classes CSS, jamais par un
attribut style (la politique de sécurité interdit les styles en ligne).
"""

import datetime

from asgor_moteur.avancement import LIBELLES
from asgor_moteur.modele import NOMS_DOMAINES

GRAVITES = ("Critique", "Élevée", "Moyenne", "Faible", "Information")
CLASSE_GRAVITE = {"Critique": "critique", "Élevée": "elevee", "Moyenne": "moyenne",
                  "Faible": "faible", "Information": "information"}
STATUTS = {
    "en_attente": ("En attente", "attente"),
    "en_cours": ("En cours", "en-cours"),
    "terminee": ("Terminé", "termine"),
    "ignoree": ("Ignoré", "ignore"),
    "echec": ("Échec", "echec"),
    "annulee": ("Annulé", "annule"),
}


def date_lisible(texte) -> str:
    """« 2026-11-15T15:32:10+01:00 » -> « 15/11/2026 à 15:32 » (heure du serveur)."""
    if not isinstance(texte, str):
        return ""
    try:
        d = datetime.datetime.fromisoformat(texte)
    except ValueError:
        return ""
    if d.tzinfo is not None:
        d = d.astimezone()
    return d.strftime("%d/%m/%Y à %H:%M")


def heure_lisible(texte) -> str:
    try:
        d = datetime.datetime.fromisoformat(texte)
    except (TypeError, ValueError):
        return ""
    return (d.astimezone() if d.tzinfo else d).strftime("%H:%M:%S")


def duree_lisible(secondes) -> str:
    if not isinstance(secondes, (int, float)) or secondes < 0:
        return ""
    secondes = int(round(secondes))
    if secondes < 60:
        return f"{secondes} s"
    minutes, secondes = divmod(secondes, 60)
    if minutes < 60:
        return f"{minutes} min {secondes:02d} s"
    heures, minutes = divmod(minutes, 60)
    return f"{heures} h {minutes:02d} min"


def ecoule_depuis(texte) -> float | None:
    try:
        d = datetime.datetime.fromisoformat(texte)
    except (TypeError, ValueError):
        return None
    if d.tzinfo is None:
        return None
    return (datetime.datetime.now().astimezone() - d).total_seconds()


def classe_note(lettre) -> str:
    if isinstance(lettre, str) and len(lettre) == 1 and lettre in "ABCDEF":
        return f"note-{lettre.lower()}"
    return "note-inconnue"


def classe_largeur(score) -> str:
    if not isinstance(score, int):
        return "largeur-0"
    return f"largeur-{max(0, min(100, score))}"


def nom_domaine(cle) -> str:
    return NOMS_DOMAINES.get(cle, cle)


def libelle_groupe(cle) -> str:
    return LIBELLES.get(cle, cle)


def commit_court(sha) -> str:
    return sha[:7] if isinstance(sha, str) else ""


def nombre(n) -> str:
    return f"{n:,}".replace(",", " ") if isinstance(n, int) else ""


def pluriel(n, singulier, pluriel_=None) -> str:
    """En français, 0 et 1 prennent le singulier : « 0 problème », « 1 problème »."""
    return singulier if isinstance(n, (int, float)) and abs(n) < 2 else (pluriel_ or singulier + "s")


FILTRES = {
    "date": date_lisible,
    "heure": heure_lisible,
    "duree": duree_lisible,
    "classe_note": classe_note,
    "classe_largeur": classe_largeur,
    "domaine": nom_domaine,
    "groupe": libelle_groupe,
    "court": commit_court,
    "nombre": nombre,
}
