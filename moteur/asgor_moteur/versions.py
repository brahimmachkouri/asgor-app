"""Comparaison simple de numéros de version, pour choisir la bonne version corrigée.

On ne compare que la partie numérique (« v8.1.2 » -> (8, 1, 2)). Une version
de préversion (« 8.2.0-beta1 ») est traitée comme la version numérique
qu'elle précède, ce qui suffit pour proposer une mise à jour.
"""

import re

_NUMERIQUE = re.compile(r"\s*v?(\d+(?:\.\d+)*)")


def cle(version) -> tuple | None:
    """(8, 1, 2) pour « v8.1.2 » ; None si la version n'est pas lisible."""
    if not isinstance(version, str):
        return None
    m = _NUMERIQUE.match(version)
    if not m:
        return None
    parties = [int(x) for x in m.group(1).split(".")[:6]]
    while len(parties) > 1 and parties[-1] == 0:
        parties.pop()
    return tuple(parties)


def comparer(a, b) -> int | None:
    """-1, 0 ou 1 ; None si l'une des deux versions n'est pas lisible."""
    ca, cb = cle(a), cle(b)
    if ca is None or cb is None:
        return None
    return (ca > cb) - (ca < cb)


_FINALE = re.compile(r"\s*v?\d+(?:\.\d+)*\s*")


def est_finale(version) -> bool:
    """Faux pour une préversion (« 5.2b1 », « 8.2.0-rc1 », « 2.0.dev3 »)."""
    return isinstance(version, str) and _FINALE.fullmatch(version) is not None


def plus_petite_superieure(installee: str, candidates) -> str:
    """Plus petite version corrigée strictement supérieure à la version installée.

    Une version finale est préférée à une préversion. Une préversion n'est
    proposée que si l'avis de sécurité ne cite aucune version finale.
    Si la version installée est inconnue ou illisible : chaîne vide (on ne
    propose pas une version au hasard).
    """
    if cle(installee) is None:
        return ""
    superieures = [c.strip() for c in candidates
                   if isinstance(c, str) and comparer(c, installee) == 1]
    if not superieures:
        return ""
    finales = [c for c in superieures if est_finale(c)]
    return min(finales or superieures, key=cle)


def depuis_plages(installee: str, plages) -> str:
    """Version corrigée de la plage qui contient la version installée.

    plages : liste de (introduite, corrigée), l'une ou l'autre pouvant être vide.
    Si aucune plage ne contient la version installée : plus petite version
    corrigée supérieure.
    """
    if cle(installee) is None:
        return ""
    for introduite, corrigee in plages:
        if not corrigee:
            continue
        apres_debut = not introduite or introduite == "0" or comparer(installee, introduite) in (0, 1)
        avant_fin = comparer(installee, corrigee) == -1
        if apres_debut and avant_fin:
            return corrigee.strip()
    return plus_petite_superieure(installee, [c for _, c in plages if c])


def depuis_contraintes_composer(installee: str, contraintes: str) -> str:
    """Lit « >=8.0.0,<8.1.0|>=8.1.0,<8.1.6 » (Composer Audit) et renvoie 8.1.6
    pour la version 8.1.2. Chaîne vide si rien ne correspond."""
    if not isinstance(contraintes, str) or cle(installee) is None:
        return ""
    plages = []
    for morceau in contraintes.split("|"):
        introduite = corrigee = ""
        for condition in morceau.split(","):
            condition = condition.strip()
            if condition.startswith(">="):
                introduite = condition[2:].strip()
            elif condition.startswith("<") and not condition.startswith("<="):
                corrigee = condition[1:].strip()
        if corrigee:
            plages.append((introduite, corrigee))
    for introduite, corrigee in plages:
        apres_debut = not introduite or comparer(installee, introduite) in (0, 1)
        if apres_debut and comparer(installee, corrigee) == -1:
            return corrigee
    return ""
