"""Validation de l'URL du dépôt à analyser (règle 3 de sécurité du moteur, README.md).

Seule forme acceptée : https://github.com/<propriétaire>/<dépôt>
(avec, au choix, un « .git » final ou une barre oblique finale).

Tout le reste est refusé : autre hôte, autre protocole, identifiants,
port, paramètres, fragment, chemin plus long, caractères inattendus.
"""

import re
from dataclasses import dataclass

LONGUEUR_MAX = 200

# Propriétaire : lettres, chiffres et tirets, 39 caractères au plus,
# pas de tiret au début ni à la fin (règles des noms de comptes GitHub).
_PROPRIETAIRE = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
# Dépôt : lettres, chiffres, point, tiret, souligné, 100 caractères au plus.
_DEPOT = r"[A-Za-z0-9._-]{1,100}"

# re.ASCII : \Z strict, aucun caractère Unicode accepté par les classes.
_MOTIF = re.compile(
    rf"https://github\.com/(?P<proprietaire>{_PROPRIETAIRE})/(?P<depot>{_DEPOT})/?",
    re.ASCII,
)


class UrlInvalide(ValueError):
    """L'URL n'est pas une adresse de dépôt GitHub acceptée."""


@dataclass(frozen=True)
class Depot:
    proprietaire: str
    nom: str

    @property
    def url_clonage(self) -> str:
        """URL reconstruite par le moteur : jamais la chaîne saisie."""
        return f"https://github.com/{self.proprietaire}/{self.nom}.git"

    @property
    def url_api(self) -> str:
        return f"https://api.github.com/repos/{self.proprietaire}/{self.nom}"

    @property
    def affichage(self) -> str:
        return f"github.com/{self.proprietaire}/{self.nom}"


def valider_url(url: object) -> Depot:
    """Renvoie le dépôt décrit par l'URL, ou lève UrlInvalide."""
    if not isinstance(url, str):
        raise UrlInvalide("l'URL doit être un texte")
    if len(url) > LONGUEUR_MAX:
        raise UrlInvalide("l'URL est trop longue")

    # fullmatch : la chaîne entière doit correspondre, sans espace ni saut
    # de ligne avant ou après. On ne nettoie rien : une URL avec des espaces
    # est refusée telle quelle.
    correspondance = _MOTIF.fullmatch(url)
    if correspondance is None:
        raise UrlInvalide(
            "forme attendue : https://github.com/<propriétaire>/<dépôt>"
        )

    proprietaire = correspondance.group("proprietaire")
    nom = correspondance.group("depot")

    if nom.endswith(".git"):
        nom = nom[: -len(".git")]
    if nom in ("", ".", ".."):
        raise UrlInvalide("nom de dépôt invalide")
    if "--" in proprietaire:
        raise UrlInvalide("nom de propriétaire invalide")

    return Depot(proprietaire=proprietaire, nom=nom)
