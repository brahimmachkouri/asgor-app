"""Format unique d'un problème et constantes communes."""

import hashlib
from dataclasses import asdict, dataclass, field

SECRETS = "secrets"
DEPENDANCES = "dependances"
CODE = "code"
DOMAINES = (SECRETS, DEPENDANCES, CODE)
NOMS_DOMAINES = {SECRETS: "Secrets", DEPENDANCES: "Dépendances", CODE: "Code"}

CRITIQUE = "Critique"
ELEVEE = "Élevée"
MOYENNE = "Moyenne"
FAIBLE = "Faible"
INFORMATION = "Information"
# De la plus grave à la moins grave.
GRAVITES = (CRITIQUE, ELEVEE, MOYENNE, FAIBLE, INFORMATION)


def rang(gravite: str) -> int:
    """0 = la plus grave."""
    return GRAVITES.index(gravite)


def plus_grave(a: str, b: str) -> str:
    return a if rang(a) <= rang(b) else b


def moins_grave_d_un_cran(gravite: str) -> str:
    return GRAVITES[min(rang(gravite) + 1, len(GRAVITES) - 1)]


def gravite_depuis_cvss(score: float) -> str:
    if score >= 9.0:
        return CRITIQUE
    if score >= 7.0:
        return ELEVEE
    if score >= 4.0:
        return MOYENNE
    return FAIBLE


def gravite_depuis_texte(texte: object, defaut: str = MOYENNE) -> str:
    """Convertit la gravité annoncée par un outil (CRITICAL, HIGH, MODERATE...)."""
    if not isinstance(texte, str):
        return defaut
    return {
        "CRITICAL": CRITIQUE,
        "HIGH": ELEVEE,
        "MODERATE": MOYENNE,
        "MEDIUM": MOYENNE,
        "LOW": FAIBLE,
    }.get(texte.strip().upper(), defaut)


def masquer_secret(secret: object) -> str:
    """Règle 5 de sécurité du moteur (README.md) : 4 premiers caractères puis ****.

    Pour un secret très court, montrer 4 caractères en révélerait la moitié
    ou plus : on ne montre alors rien.
    """
    if not isinstance(secret, str) or len(secret) <= 8:
        return "****"
    return secret[:4] + "****"


@dataclass
class Probleme:
    domaine: str
    gravite: str
    titre: str
    fichier: str = ""
    ligne: int = 0
    outils: list = field(default_factory=list)
    regle: str = ""
    explication: str = ""
    correction: str = ""
    # Secrets
    commit: str = ""
    secret_masque: str = ""
    occurrences: int = 1
    a_verifier: bool = False   # secret dans un fichier de test, doc, exemple (BAREME.md § 6)
    ecarte: bool = False       # écarté comme faux positif par l'équipe
    # Dépendances
    paquet: str = ""
    version: str = ""
    version_corrigee: str = ""
    identifiants: list = field(default_factory=list)
    # Code
    categorie: str = ""
    flux: bool = False  # trouvé par l'analyse de flux (Psalm)
    references: list = field(default_factory=list)

    @property
    def empreinte(self) -> str:
        """Identifiant stable : le même problème garde le même identifiant
        d'une analyse à l'autre. Ne contient jamais le secret lui-même."""
        if self.domaine == SECRETS:
            parties = [self.regle, self.fichier]   # un problème par fichier et par règle
        elif self.domaine == DEPENDANCES:
            parties = [self.paquet.lower(), identifiant_principal(self.identifiants), self.fichier]
        else:
            parties = [self.categorie or self.regle, self.fichier, str(self.ligne)]
        texte = "\x1f".join([self.domaine] + parties)
        return hashlib.sha256(texte.encode("utf-8", "replace")).hexdigest()[:16]

    def en_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.empreinte
        d["outils"] = sorted(set(self.outils))
        d["identifiants"] = sorted(set(self.identifiants))
        # On retire les champs vides pour garder un rapport lisible.
        return {k: v for k, v in d.items() if v not in ("", [], 0, False) or k in ("ligne",)}


def identifiant_principal(identifiants) -> str:
    """Préfère un CVE, puis un GHSA, puis le premier par ordre alphabétique."""
    ids = sorted({i for i in identifiants if isinstance(i, str) and i})
    for prefixe in ("CVE-", "GHSA-"):
        for i in ids:
            if i.upper().startswith(prefixe):
                return i
    return ids[0] if ids else ""
