"""Sécurité du service web."""

import hmac
import re
import secrets
import urllib.parse

TAILLE_MAX_CORPS = 4096
TAILLE_MAX_CORPS_MARQUAGE = 16 * 1024   # 500 cases cochées au plus (BAREME.md § 6 c)
COOKIE_CSRF = "csrf"

# Aucune ressource externe, aucun script, aucun style en ligne.
CSP = ("default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; "
       "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")

ENTETES = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    # same-origin, pas no-referrer : avec no-referrer, le navigateur envoie
    # « Origin: null » sur les formulaires POST, même vers le même site (norme
    # Fetch), et verifier_origine les refuse (vu au premier essai
    # depuis un navigateur). same-origin n'envoie toujours rien aux autres sites.
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


# Envoyé seulement en HTTPS (derrière Caddy). Pas de « includeSubDomains » :
# Caddy sert d'autres noms du même domaine, qu'ASGOR n'a pas à engager.
HSTS = "max-age=31536000"


class RequeteRefusee(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def nouveau_jeton() -> str:
    return secrets.token_urlsafe(32)


def jeton_valide(jeton) -> bool:
    return isinstance(jeton, str) and 20 <= len(jeton) <= 100 and jeton.replace("-", "").replace("_", "").isalnum()


async def lire_formulaire(requete, taille_max: int = TAILLE_MAX_CORPS, nb_champs_max: int = 20,
                          multiples: tuple = ()) -> dict:
    """Lit un formulaire « application/x-www-form-urlencoded » de 4 Ko au plus.

    Pas de python-multipart : parse_qs de la bibliothèque standard suffit.
    Chaque champ n'a qu'une valeur (la première), sauf ceux de « multiples »
    (liste de toutes les valeurs, ex. les cases cochées).
    """
    type_contenu = requete.headers.get("content-type", "").split(";")[0].strip().lower()
    if type_contenu != "application/x-www-form-urlencoded":
        raise RequeteRefusee(415, "type de formulaire non accepté")
    longueur = requete.headers.get("content-length")
    if longueur is not None:
        try:
            if int(longueur) > taille_max:
                raise RequeteRefusee(413, "formulaire trop gros")
        except ValueError:
            raise RequeteRefusee(400, "en-tête Content-Length invalide") from None
    corps = b""
    async for morceau in requete.stream():
        corps += morceau
        if len(corps) > taille_max:
            raise RequeteRefusee(413, "formulaire trop gros")
    try:
        champs = urllib.parse.parse_qs(corps.decode("utf-8"), keep_blank_values=True,
                                       strict_parsing=False, max_num_fields=nb_champs_max)
    except (UnicodeDecodeError, ValueError):
        raise RequeteRefusee(400, "formulaire illisible") from None
    return {cle: (valeurs if cle in multiples else valeurs[0]) for cle, valeurs in champs.items()}


def verifier_origine(requete) -> None:
    """Refuse un POST venu d'un autre site (en plus du jeton CSRF)."""
    origine = requete.headers.get("origin")
    if origine is None or origine == "null":
        if origine == "null":
            raise RequeteRefusee(403, "origine de la requête refusée")
        return  # navigateur ancien : le jeton CSRF suffit
    hote = requete.headers.get("host", "")
    if urllib.parse.urlsplit(origine).netloc.lower() != hote.lower():
        raise RequeteRefusee(403, "origine de la requête refusée")


def verifier_csrf(requete, formulaire: dict) -> None:
    """Double envoi : le cookie et le champ caché doivent être identiques."""
    verifier_origine(requete)
    cookie = requete.cookies.get(COOKIE_CSRF)
    champ = formulaire.get("csrf")
    if not jeton_valide(cookie) or not isinstance(champ, str) \
            or not hmac.compare_digest(cookie.encode(), champ.encode()):
        raise RequeteRefusee(403, "jeton de sécurité absent ou invalide : rechargez la page")


_NOM_GITHUB = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_NOM_DEPOT = re.compile(r"[A-Za-z0-9._-]{1,100}")
_COMMIT = re.compile(r"[0-9a-f]{7,64}")


def lien_github(depot, probleme) -> str | None:
    """Lien « Voir sur GitHub » vers le fichier, au commit et à la ligne exacts
    (BAREME.md § 6). Construit à partir de valeurs revalidées, jamais recopié."""
    if not isinstance(depot, dict) or not isinstance(probleme, dict):
        return None
    proprietaire, nom = depot.get("proprietaire"), depot.get("nom")
    commit = probleme.get("commit") or depot.get("commit")
    fichier, ligne = probleme.get("fichier"), probleme.get("ligne")
    if not (isinstance(proprietaire, str) and _NOM_GITHUB.fullmatch(proprietaire)
            and isinstance(nom, str) and _NOM_DEPOT.fullmatch(nom) and nom not in (".", "..")
            and isinstance(commit, str) and _COMMIT.fullmatch(commit)
            and isinstance(fichier, str) and 0 < len(fichier) <= 400):
        return None
    morceaux = fichier.split("/")
    if any(m in ("", ".", "..") for m in morceaux) or any(ord(c) < 32 for c in fichier):
        return None
    lien = (f"https://github.com/{proprietaire}/{nom}/blob/{commit}/"
            + "/".join(urllib.parse.quote(m, safe="") for m in morceaux))
    if isinstance(ligne, int) and not isinstance(ligne, bool) and ligne > 0:
        lien += f"#L{ligne}"
    return lien


def lien_sur(url) -> str | None:
    """Adresse cliquable seulement si elle commence par https:// (jamais javascript:)."""
    if not isinstance(url, str) or len(url) > 500:
        return None
    if not url.startswith("https://"):
        return None
    if any(c in url for c in "\"'<>\\ \t\r\n"):
        return None
    return url
