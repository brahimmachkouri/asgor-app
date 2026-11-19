"""Calcul de la note selon BAREME.md (barème version 3)."""

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
    NOMS_DOMAINES,
    SECRETS,
    rang,
)

LETTRES = ("A", "B", "C", "D", "E", "F")

VERSION_BAREME = 3

# État de l'évaluation d'un domaine (BAREME.md § 3 b).
COMPLET = "complet"
PARTIEL = "partiel"
NON_EVALUE = "non évalué"
HORS_PERIMETRE = "hors périmètre"

# Ce qu'on ne sait pas quand un domaine n'a pas pu être évalué.
_CE_QU_ON_NE_SAIT_PAS = {
    SECRETS: "ASGOR ne peut pas dire si le dépôt contient des secrets",
    DEPENDANCES: "ASGOR ne peut pas dire si les dépendances du dépôt ont des failles connues",
    CODE: "ASGOR ne peut pas dire si le code du dépôt contient des failles "
          "(injection SQL, XSS, injection de commande…)",
}
NB_MAX_FICHIERS_NON_ANALYSES = 500   # le moteur n'en garde pas plus

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
    # Case « Analyser l'historique de la branche par défaut » décochée
    historique_non_analyse: bool = False
    # Outils qui ont donné un résultat : {domaine: [noms d'outils]}. None : inconnu
    # (rapport du barème 2, relu après un écart) ; un échec rend alors le domaine
    # « partiel », comme avant.
    outils_reussis: dict | None = None
    # Cause de l'échec de chaque outil : {nom de l'outil: raison}
    raisons_echec: dict = field(default_factory=dict)
    # Domaines sans rien à analyser : {domaine: raison} (langage non pris en charge…)
    hors_perimetre: dict = field(default_factory=dict)
    # Fichiers qu'un outil n'a pas pu lire : {domaine: ["chemin (outil : raison)", ...]}
    fichiers_non_analyses: dict = field(default_factory=dict)


def _liste_fr(noms) -> str:
    noms = list(noms)
    if len(noms) <= 1:
        return "".join(noms)
    return ", ".join(noms[:-1]) + " et " + noms[-1]


def _echecs_detailles(en_echec, contexte) -> str:
    """« Gitleaks (délai dépassé) » ; plusieurs outils séparés par « et »."""
    return _liste_fr(f"{o} ({contexte.raisons_echec[o]})" if contexte.raisons_echec.get(o) else o
                     for o in en_echec)


def etat_domaine(domaine, problemes_du_domaine, contexte) -> tuple:
    """(état, raison) d'un domaine. problemes_du_domaine : écartés compris."""
    en_echec = sorted(contexte.outils_en_echec.get(domaine, []))
    reussis = None if contexte.outils_reussis is None else contexte.outils_reussis.get(domaine, [])
    non_lus = contexte.fichiers_non_analyses.get(domaine, [])
    nom = NOMS_DOMAINES[domaine]
    if (domaine in contexte.hors_perimetre and not en_echec and not problemes_du_domaine
            and not non_lus):
        return HORS_PERIMETRE, contexte.hors_perimetre[domaine]
    if en_echec and reussis is not None and not reussis:
        verbe = "n'a" if len(en_echec) == 1 else "n'ont"
        return NON_EVALUE, (
            f"domaine {nom} non évalué : {_echecs_detailles(en_echec, contexte)} {verbe} pas "
            f"donné de résultat. Sans cette analyse, {_CE_QU_ON_NE_SAIT_PAS[domaine]}. "
            "Relancez l'analyse ; si l'échec se répète, prévenez l'administrateur")
    raisons = []
    if en_echec:
        raisons.append(f"échec de {_echecs_detailles(en_echec, contexte)}")
    if non_lus:
        n = len(non_lus)
        raisons.append(f"{n} fichier{'s' if n > 1 else ''} n'{'ont' if n > 1 else 'a'} "
                       "pas pu être analysé" + ("s" if n > 1 else ""))
    if domaine == SECRETS and contexte.historique_non_analyse:
        raisons.append("historique Git non analysé")
    if raisons:
        return PARTIEL, f"domaine {nom} évalué en partie : " + " ; ".join(raisons)
    return COMPLET, ""


def phrase_portee(domaines: dict) -> str:
    """« note calculée sur Secrets et Dépendances. Code : hors périmètre (…). »

    Vide quand les trois domaines sont notés."""
    notes = [NOMS_DOMAINES[d] for d in DOMAINES if domaines[d]["lettre"] is not None]
    if len(notes) == len(DOMAINES):
        return ""
    if notes:
        debut = f"note calculée sur {_liste_fr(notes)}."
    else:
        debut = "aucun domaine n'a pu être noté."
    autres = []
    for d in DOMAINES:
        if domaines[d]["lettre"] is None:
            if domaines[d]["etat"] == HORS_PERIMETRE:
                autres.append(f"{NOMS_DOMAINES[d]} : hors périmètre ({domaines[d]['raison']}).")
            else:
                autres.append(f"{NOMS_DOMAINES[d]} : non évalué (raison détaillée dans le rapport).")
    return " ".join([debut] + autres)


def noter(problemes, contexte: Contexte | None = None) -> dict:
    contexte = contexte or Contexte()

    domaines = {}
    note = None   # aucun domaine noté : pas de note globale
    tous = list(problemes)
    problemes = [p for p in problemes if not p.ecarte]   # faux positifs écartés par l'équipe
    for domaine in DOMAINES:
        du_domaine = [p for p in problemes if p.domaine == domaine]
        etat, raison = etat_domaine(domaine, [p for p in tous if p.domaine == domaine], contexte)
        if etat in (COMPLET, PARTIEL):
            score = score_domaine(du_domaine)
            lettre = lettre_depuis_score(score)
            note = lettre if note is None else pire_lettre(note, lettre)
        else:
            score = lettre = None   # jamais « 100 » pour un domaine qu'on n'a pas vu
        reussis = (None if contexte.outils_reussis is None
                   else sorted(contexte.outils_reussis.get(domaine, [])))
        domaines[domaine] = {
            "score": score,
            "lettre": lettre,
            "problemes": len(du_domaine),
            "etat": etat,
            "raison": raison,
            "outils_en_echec": sorted(contexte.outils_en_echec.get(domaine, [])),
            "outils_reussis": reussis,
            "raisons_echec": {o: contexte.raisons_echec[o]
                              for o in contexte.outils_en_echec.get(domaine, [])
                              if contexte.raisons_echec.get(o)},
            "hors_perimetre": contexte.hors_perimetre.get(domaine, ""),
            "fichiers_non_analyses": list(contexte.fichiers_non_analyses.get(domaine, [])),
            "nb_fichiers_non_analyses": len(contexte.fichiers_non_analyses.get(domaine, [])),
        }
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
        etat, raison = domaines[domaine]["etat"], domaines[domaine]["raison"]
        if etat == NON_EVALUE:
            plafonner("C", raison)
        elif etat == PARTIEL:
            # L'historique non analysé a déjà sa règle (B) : pas de doublon.
            if domaines[domaine]["outils_en_echec"] or domaines[domaine]["nb_fichiers_non_analyses"]:
                plafonner("B", raison)

    if any(rang(p.gravite) <= rang(MOYENNE) for p in problemes):
        plafonner("B", "au moins un problème de gravité moyenne ou plus")

    if note is not None:
        for plafonnement in plafonnements:
            note = pire_lettre(note, plafonnement["note_max"])

    # Raisons affichées : les règles qui fixent la note finale, même quand le
    # score d'un domaine donnait déjà cette lettre (ex. secret détecté : F).
    utiles = [p for p in plafonnements if p["note_max"] == note]
    if note is None:
        utiles = [p for p in plafonnements if p["note_max"] == "C"]   # les domaines non évalués

    return {
        "version_bareme": VERSION_BAREME,
        "globale": note,
        "portee": phrase_portee(domaines),
        "avant_plafonnement": avant_plafonnement,
        "plafonnements": utiles,
        "tous_les_plafonnements": plafonnements,
        "domaines": domaines,
    }
