"""Suppression des doublons quand plusieurs outils signalent la même chose."""

from .modele import CODE, DEPENDANCES, plus_grave, rang

# Outils qui ne donnent pas de gravité : leur valeur par défaut ne doit pas
# l'emporter sur celle d'un outil qui en donne une.
_SANS_GRAVITE = {"pip-audit"}


def _fusionner(a, b):
    """Complète le problème a avec les informations de b."""
    a_sans = set(a.outils) <= _SANS_GRAVITE
    b_sans = set(b.outils) <= _SANS_GRAVITE
    if a_sans and not b_sans:
        a.gravite = b.gravite
    elif not b_sans or a_sans:
        a.gravite = plus_grave(a.gravite, b.gravite)
    a.outils = sorted(set(a.outils) | set(b.outils))
    a.identifiants = sorted(set(a.identifiants) | set(b.identifiants))
    a.references = list(dict.fromkeys(a.references + b.references))[:5]
    a.flux = a.flux or b.flux
    for champ in ("version", "version_corrigee", "explication", "correction",
                  "categorie", "fichier", "regle"):
        if not getattr(a, champ) and getattr(b, champ):
            setattr(a, champ, getattr(b, champ))
    # Un titre générique « Faille connue dans … » cède la place à un vrai titre.
    if a.titre.startswith("Faille connue dans ") and not b.titre.startswith("Faille connue dans "):
        a.titre = b.titre
    return a


def _meme_faille(a, b) -> bool:
    """Même paquet, même fichier de verrouillage et au moins un identifiant commun.

    La même faille dans deux fichiers de verrouillage (deux composer.lock d'un
    même dépôt, par exemple) reste deux problèmes : chacun se corrige à part.
    Un fichier inconnu (vide) ne bloque pas la fusion.
    """
    return (a.paquet.lower() == b.paquet.lower()
            and (a.fichier == b.fichier or not a.fichier or not b.fichier)
            and bool(set(a.identifiants) & set(b.identifiants)))


def _fusionner_dependances(problemes) -> list:
    """Même faille signalée par plusieurs outils (voir _meme_faille) : un seul problème."""
    gardes = []
    for p in problemes:
        cible = None
        if p.identifiants:
            for g in gardes:
                if _meme_faille(g, p):
                    cible = g
                    break
        if cible is None:
            gardes.append(p)
            continue
        _fusionner(cible, p)
        # La fusion peut relier deux groupes jusque-là séparés.
        for autre in [g for g in gardes if g is not cible]:
            if _meme_faille(autre, cible):
                _fusionner(cible, autre)
                gardes.remove(autre)
    return gardes


ECART_MAX_LIGNES = 3


def _fusionner_code(problemes) -> list:
    """Deux passes.

    1. Même fichier, même ligne, même catégorie (ou même règle) : un seul problème.
    2. Même fichier, même catégorie, au plus 3 lignes d'écart, et signalés par
       des outils différents : un seul problème. Exemple : Psalm signale la ligne
       où la requête SQL est exécutée, Opengrep celle où elle est construite.
       Deux résultats du même outil ne sont jamais fusionnés par cette passe :
       ce sont probablement deux failles distinctes.
    """
    exacts = {}
    for p in problemes:
        cle = (p.fichier, p.ligne, p.categorie or p.regle)
        if cle in exacts:
            _fusionner(exacts[cle], p)
        else:
            exacts[cle] = p

    gardes = []
    par_groupe = {}
    for p in sorted(exacts.values(), key=lambda q: (q.fichier, q.categorie, q.ligne)):
        if not p.categorie or not p.ligne:
            gardes.append(p)
            continue
        groupe = par_groupe.setdefault((p.fichier, p.categorie), [])
        proches = [g for g in groupe
                   if abs(g.ligne - p.ligne) <= ECART_MAX_LIGNES
                   and not set(g.outils) & set(p.outils)]
        if not proches:
            groupe.append(p)
            gardes.append(p)
            continue
        cible = min(proches, key=lambda g: abs(g.ligne - p.ligne))
        # On garde la ligne donnée par l'analyse de flux : c'est là que la
        # donnée reçue est utilisée.
        ligne_flux = p.ligne if (p.flux and not cible.flux) else cible.ligne
        _fusionner(cible, p)
        cible.ligne = ligne_flux
    return gardes


def supprimer_doublons(problemes) -> list:
    dependances = [p for p in problemes if p.domaine == DEPENDANCES]
    code = [p for p in problemes if p.domaine == CODE]
    autres = [p for p in problemes if p.domaine not in (DEPENDANCES, CODE)]
    resultat = autres + _fusionner_dependances(dependances) + _fusionner_code(code)
    resultat.sort(key=lambda p: (rang(p.gravite), p.domaine, p.fichier, p.ligne, p.titre))
    return resultat
