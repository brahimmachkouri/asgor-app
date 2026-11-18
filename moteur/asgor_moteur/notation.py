"""Calcul de la note selon BAREME.md (barème version 2)."""

import math
from dataclasses import dataclass, field

from .modele import (
    CODE,
    CRITIQUE,
    DEPENDANCES,
    DOMAINES,
    ELEVEE,
    FAIBLE,
    MOYENNE,
    SECRETS,
    rang,
)

LETTRES = ("A", "B", "C", "D", "E", "F")

VERSION_BAREME = 2

# BAREME.md § 3 : chaque problème vaut tant de « problèmes élevés » ;
# chaque doublement du total retire POINTS_PAR_DOUBLEMENT points.
EQUIVALENTS = {CRITIQUE: 4.0, ELEVEE: 1.0, MOYENNE: 0.3, FAIBLE: 0.05}
POINTS_PAR_DOUBLEMENT = 15
# Domaine Secrets : un secret garde le score dans la zone F, un secret
# « à vérifier » dans la zone D (cohérence avec les plafonnements).
SCORE_MAX_SECRET = 29
SCORE_MAX_SECRET_A_VERIFIER = 59

# Catégories de l'analyse de flux qui plafonnent la note à C.
CATEGORIES_FLUX_PLAFONNEES = ("injection-sql", "xss", "injection-commande")


def lettre_depuis_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    if score >= 30:
        return "E"
    return "F"


def pire_lettre(a: str, b: str) -> str:
    return a if LETTRES.index(a) >= LETTRES.index(b) else b


def gravites_comptees(problemes) -> list:
    """Gravités prises en compte. Une dépendance (un paquet dans un fichier de
    verrouillage) compte une seule fois, avec sa gravité la plus haute."""
    autres, par_dependance = [], {}
    for p in problemes:
        if p.gravite not in EQUIVALENTS:
            continue
        if p.domaine == DEPENDANCES and p.paquet:
            cle = (p.paquet.lower(), p.fichier)
            if cle not in par_dependance or rang(p.gravite) < rang(par_dependance[cle]):
                par_dependance[cle] = p.gravite
        else:
            autres.append(p.gravite)
    return autres + list(par_dependance.values())


def score_domaine(problemes) -> int:
    total = sum(EQUIVALENTS[g] for g in gravites_comptees(problemes))
    score = max(0, int(round(100 - POINTS_PAR_DOUBLEMENT * math.log2(1 + total))))
    secrets = [p for p in problemes if p.domaine == SECRETS]
    if any(not p.a_verifier for p in secrets):
        score = min(score, SCORE_MAX_SECRET)
    elif secrets:
        score = min(score, SCORE_MAX_SECRET_A_VERIFIER)
    return score


@dataclass
class Contexte:
    """Ce que le moteur sait en plus de la liste des problèmes."""

    # Outils en échec ou hors délai : {domaine: [noms d'outils]}
    outils_en_echec: dict = field(default_factory=dict)
    # Raisons « application sans fichier de verrouillage »
    sans_verrouillage: list = field(default_factory=list)
    # Case « Analyser tout l'historique Git » décochée
    historique_non_analyse: bool = False


def noter(problemes, contexte: Contexte | None = None) -> dict:
    contexte = contexte or Contexte()

    domaines = {}
    note = "A"
    problemes = [p for p in problemes if not p.ecarte]   # faux positifs écartés par l'équipe
    for domaine in DOMAINES:
        du_domaine = [p for p in problemes if p.domaine == domaine]
        score = score_domaine(du_domaine)
        lettre = lettre_depuis_score(score)
        en_echec = sorted(contexte.outils_en_echec.get(domaine, []))
        domaines[domaine] = {
            "score": score,
            "lettre": lettre,
            "problemes": len(du_domaine),
            "evaluation": "incomplète" if en_echec else "complète",
            "outils_en_echec": en_echec,
        }
        note = pire_lettre(note, lettre)
    avant_plafonnement = note

    plafonnements = []

    def plafonner(note_max: str, raison: str) -> None:
        plafonnements.append({"note_max": note_max, "raison": raison})

    secrets = [p for p in problemes if p.domaine == SECRETS and not p.a_verifier]
    a_verifier = [p for p in problemes if p.domaine == SECRETS and p.a_verifier]
    if secrets:
        n = len(secrets)
        plafonner("F", f"{n} secret{'s' if n > 1 else ''} détecté{'s' if n > 1 else ''} "
                       "dans les fichiers ou dans l'historique Git")
    if a_verifier:
        n = len(a_verifier)
        plafonner("D", f"{n} secret{'s' if n > 1 else ''} à vérifier dans des fichiers de test, "
                       "de documentation ou d'exemple")

    critiques = [p for p in problemes if p.gravite == CRITIQUE and p.domaine != SECRETS]
    if critiques:
        n = len(critiques)
        plafonner("F", f"{n} faille{'s' if n > 1 else ''} critique{'s' if n > 1 else ''}")

    flux = [p for p in problemes
            if p.domaine == CODE and p.flux and p.categorie in CATEGORIES_FLUX_PLAFONNEES]
    if flux:
        plafonner("C", "injection SQL, XSS ou injection de commande détectée "
                       "par l'analyse de flux (Psalm)")

    corrigeables = [p for p in problemes
                    if p.domaine == DEPENDANCES and p.gravite == ELEVEE and p.version_corrigee]
    if corrigeables:
        plafonner("B", "dépendance avec une faille élevée et une version corrigée disponible")

    if contexte.historique_non_analyse:
        plafonner("B", "historique Git non analysé : les secrets des anciens commits "
                       "n'ont pas été cherchés")

    for raison in contexte.sans_verrouillage:
        plafonner("B", f"analyse des dépendances incomplète : {raison}")

    for domaine in DOMAINES:
        en_echec = domaines[domaine]["outils_en_echec"]
        if en_echec:
            plafonner("B", f"domaine {domaine} non évalué entièrement : "
                           f"échec de {', '.join(en_echec)}")

    if any(rang(p.gravite) <= rang(MOYENNE) for p in problemes):
        plafonner("B", "au moins un problème de gravité moyenne ou plus")

    for plafonnement in plafonnements:
        note = pire_lettre(note, plafonnement["note_max"])

    # Raisons affichées : les règles qui fixent la note finale, même quand le
    # score d'un domaine donnait déjà cette lettre (ex. secret détecté : F).
    utiles = [p for p in plafonnements if p["note_max"] == note]

    return {
        "version_bareme": VERSION_BAREME,
        "globale": note,
        "avant_plafonnement": avant_plafonnement,
        "plafonnements": utiles,
        "tous_les_plafonnements": plafonnements,
        "domaines": domaines,
    }
