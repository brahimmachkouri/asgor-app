"""Avancement d'une analyse, tel qu'il est affiché.

Le moteur enchaîne une vingtaine d'étapes techniques. L'utilisateur en voit
9 groupes, toujours dans le même ordre.
"""

# (clé, libellé)
GROUPES = (
    ("clonage", "Clonage du dépôt"),
    ("langages", "Détection des langages"),
    ("secrets", "Secrets"),
    ("dependances", "Dépendances"),
    ("flux", "Analyse de flux PHP"),
    ("qualite", "Qualité du code PHP"),
    ("regles", "Règles de sécurité"),
    ("python", "Code Python"),
    ("note", "Calcul de la note"),
)
CLES = tuple(cle for cle, _ in GROUPES)
LIBELLES = dict(GROUPES)

EN_ATTENTE = "en_attente"
EN_COURS = "en_cours"
TERMINEE = "terminee"
IGNOREE = "ignoree"
ECHEC = "echec"
ANNULEE = "annulee"


class Observateur:
    """Reçoit l'avancement d'une analyse. Ne fait rien par défaut.

    Le worker en dérive une classe qui écrit dans la base ; asgor-scan une
    classe qui écrit dans le terminal.
    """

    def groupe_commence(self, cle: str) -> None:
        pass

    def groupe_termine(self, cle: str, statut: str, detail: str, duree_s: float) -> None:
        pass

    def depot_connu(self, commit: str, branche: str, nb_commits: int) -> None:
        pass


class ObservateurTerminal(Observateur):
    def __init__(self, afficher=print):
        self.afficher = afficher

    def groupe_commence(self, cle: str) -> None:
        self.afficher(f"== {LIBELLES[cle]}")

    def groupe_termine(self, cle: str, statut: str, detail: str, duree_s: float) -> None:
        if statut == IGNOREE:
            self.afficher(f"== {LIBELLES[cle]} : ignoré ({detail})")
        elif statut != TERMINEE or detail:
            texte = {TERMINEE: "terminé", ECHEC: "terminé avec un échec",
                     ANNULEE: "annulé"}.get(statut, statut)
            self.afficher(f"   {texte}{' — ' + detail if detail else ''}")


def nombre_fr(n: int) -> str:
    """1640 -> « 1 640 » (espace insécable fine, comme en français)."""
    return f"{n:,}".replace(",", " ")
