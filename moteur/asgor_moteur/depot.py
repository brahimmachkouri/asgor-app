"""Inventaire du dépôt cloné : langages, fichiers de dépendances, verrouillage.

Le moteur ne lit ici que des noms de fichiers et quelques petits fichiers
de déclaration (JSON, TOML, texte). Il ne suit aucun lien symbolique.
"""

import os
import re
import tomllib
from dataclasses import dataclass, field

from . import fichiers

DOSSIERS_IGNORES = {".git", "vendor", "node_modules", ".venv", "venv", "__pycache__"}
NB_MAX_FICHIERS = 300_000
NB_MAX_MANIFESTES = 20
TAILLE_MAX_MANIFESTE = 2 * 1024 * 1024

_REQUIREMENTS = re.compile(r"requirements[A-Za-z0-9._-]*\.txt")
VERROUS_PYTHON = ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock")
# Types de composer.json traités comme des bibliothèques (BAREME.md § 5).
TYPES_BIBLIOTHEQUE = ("library", "symfony-bundle")

# Langages dont le code n'est pas analysé par ASGOR (domaine Code : PHP et Python
# seulement). Comptés pour le bilan de couverture (BAREME.md § 3 b).
LANGAGES_NON_PRIS_EN_CHARGE = {
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript", ".tsx": "TypeScript",
    ".vue": "Vue", ".svelte": "Svelte",
    ".go": "Go", ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala",
    ".rb": "Ruby", ".cs": "C#", ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++",
    ".cxx": "C++", ".hpp": "C++", ".rs": "Rust", ".swift": "Swift", ".dart": "Dart",
    ".pl": "Perl", ".pm": "Perl", ".lua": "Lua", ".sh": "Shell", ".bash": "Shell",
}

# Fichiers de dépendances que lisent OSV-Scanner ou Trivy (en plus de ceux de PHP et
# de Python ci-dessous). Aucun : domaine Dépendances « hors périmètre ».
FICHIERS_DEPENDANCES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "bun.lock", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
    "Gemfile", "Gemfile.lock", "pom.xml", "build.gradle", "build.gradle.kts",
    "gradle.lockfile", "packages.config", "packages.lock.json", "mix.exs", "mix.lock",
    "pubspec.yaml", "pubspec.lock", "Podfile.lock", "Package.resolved", "conanfile.txt",
    "conan.lock", "renv.lock", "setup.py", "setup.cfg",
}
SUFFIXES_DEPENDANCES = (".csproj", ".gemspec")


@dataclass
class Inventaire:
    nb_php: int = 0
    nb_python: int = 0
    # Chemins relatifs à la racine du dépôt
    composer_json: list = field(default_factory=list)
    composer_lock: list = field(default_factory=list)
    requirements: list = field(default_factory=list)
    verrous_python: list = field(default_factory=list)
    pyproject: list = field(default_factory=list)
    pipfile: list = field(default_factory=list)
    dossiers_tiers: list = field(default_factory=list)  # vendor, node_modules…
    # Fichiers de code non analysés : {langage: nombre} (bibliothèques .min.js exclues)
    non_pris_en_charge: dict = field(default_factory=dict)
    nb_autres_dependances: int = 0   # package.json, go.mod… (FICHIERS_DEPENDANCES)
    tronque: bool = False

    @property
    def fichiers_dependances(self) -> bool:
        return bool(self.composer_json or self.composer_lock or self.requirements
                    or self.verrous_python or self.pyproject or self.pipfile
                    or self.nb_autres_dependances)

    @property
    def php(self) -> bool:
        return self.nb_php > 0

    @property
    def python(self) -> bool:
        return self.nb_python > 0

    @property
    def langages(self) -> list:
        return [nom for nom, present in (("PHP", self.php), ("Python", self.python)) if present]


def inventorier(racine: str) -> Inventaire:
    inv = Inventaire()
    vus = 0
    for dossier, sous_dossiers, noms in os.walk(racine, followlinks=False):
        # Ordre alphabétique : l'ordre rendu par le système de fichiers change d'une
        # machine à l'autre (vu le 19/11/2026 entre la VM et l'image Docker sur pygoat).
        # Avec les plafonds (NB_MAX_MANIFESTES, NB_MAX_FICHIERS…), les fichiers retenus,
        # donc les résultats, en dépendaient.
        sous_dossiers.sort()
        noms.sort()
        relatif = os.path.relpath(dossier, racine)
        relatif = "" if relatif == "." else relatif
        for nom in list(sous_dossiers):
            if nom in DOSSIERS_IGNORES:
                sous_dossiers.remove(nom)
                if nom != ".git" and len(inv.dossiers_tiers) < 200:
                    inv.dossiers_tiers.append(os.path.join(relatif, nom))
        for nom in noms:
            vus += 1
            if vus > NB_MAX_FICHIERS:
                inv.tronque = True
                return inv
            chemin = os.path.join(relatif, nom)
            if nom.endswith(".php"):
                inv.nb_php += 1
            elif nom.endswith(".py"):
                inv.nb_python += 1
            elif not nom.endswith(".min.js"):
                langage = LANGAGES_NON_PRIS_EN_CHARGE.get(os.path.splitext(nom)[1].lower())
                if langage:
                    inv.non_pris_en_charge[langage] = inv.non_pris_en_charge.get(langage, 0) + 1
            if nom in FICHIERS_DEPENDANCES or nom.endswith(SUFFIXES_DEPENDANCES):
                inv.nb_autres_dependances += 1
            cible = None
            if nom == "composer.json":
                cible = inv.composer_json
            elif nom == "composer.lock":
                cible = inv.composer_lock
            elif _REQUIREMENTS.fullmatch(nom):
                cible = inv.requirements
            elif nom in VERROUS_PYTHON:
                cible = inv.verrous_python
            elif nom == "pyproject.toml":
                cible = inv.pyproject
            elif nom == "Pipfile":
                cible = inv.pipfile
            if cible is not None and len(cible) < NB_MAX_MANIFESTES:
                cible.append(chemin)
    for liste in (inv.composer_json, inv.composer_lock, inv.requirements,
                  inv.verrous_python, inv.pyproject, inv.pipfile, inv.dossiers_tiers):
        liste.sort(key=lambda c: (c.count("/"), c))
    return inv


def requirements_epingle(texte: str) -> bool:
    """Vrai si chaque dépendance du fichier a une version exacte (==)."""
    for ligne in texte.replace("\\\n", " ").splitlines():
        ligne = ligne.split(" #")[0].strip()
        if not ligne or ligne.startswith("#"):
            continue
        if ligne.startswith(("--hash", "--index-url", "--extra-index-url", "--find-links",
                             "--trusted-host", "-i ", "-f ", "--only-binary", "--no-binary",
                             "--prefer-binary", "--require-hashes", "--pre")):
            continue
        if ligne.startswith(("-r", "-c", "--requirement", "--constraint")):
            continue  # autre fichier : il est vérifié de son côté s'il s'appelle requirements*.txt
        exigence = ligne.split(";")[0]
        if ligne.startswith(("-e", "--editable")) or "://" in exigence:
            return False
        if not re.search(r"(?<![=!<>~])===?\s*[A-Za-z0-9]", exigence) or "*" in exigence:
            return False
    return True


def _dependances_composer(donnees: dict) -> bool:
    """Vrai si composer.json déclare au moins un paquet (hors php et extensions)."""
    for cle in ("require", "require-dev"):
        section = donnees.get(cle)
        if isinstance(section, dict):
            for nom in section:
                if isinstance(nom, str) and "/" in nom:
                    return True
    return False


def _dependances_pyproject(donnees: dict) -> bool:
    projet = donnees.get("project")
    if isinstance(projet, dict) and projet.get("dependencies"):
        return True
    poetry = donnees.get("tool", {}).get("poetry") if isinstance(donnees.get("tool"), dict) else None
    if isinstance(poetry, dict) and isinstance(poetry.get("dependencies"), dict):
        return any(nom.lower() != "python" for nom in poetry["dependencies"])
    return False


def verifier_verrouillage(racine: str, inv: Inventaire) -> tuple:
    """Applique BAREME.md § 5.

    Renvoie (plafonnements, avertissements) : deux listes de phrases.
    Dans le doute, le dépôt est traité comme une application (cas le plus sévère).
    """
    plafonnements = []
    avertissements = []

    def dossier_de(chemin: str) -> str:
        return os.path.dirname(chemin)

    def affichage(chemin: str) -> str:
        return chemin or "."

    # ---- PHP
    dossiers_verrouilles = {dossier_de(c) for c in inv.composer_lock}
    for chemin in inv.composer_json:
        if dossier_de(chemin) in dossiers_verrouilles:
            continue
        try:
            donnees = fichiers.lire_json(os.path.join(racine, chemin), TAILLE_MAX_MANIFESTE)
        except fichiers.LectureRefusee:
            donnees = None
        if not isinstance(donnees, dict):
            plafonnements.append(f"{chemin} est illisible et n'a pas de composer.lock")
            continue
        if not _dependances_composer(donnees):
            continue
        if donnees.get("type") in TYPES_BIBLIOTHEQUE:
            avertissements.append(
                f"{chemin} : bibliothèque sans composer.lock. Les versions exactes "
                "des dépendances ne sont pas connues.")
        else:
            plafonnements.append(f"{chemin} n'a pas de composer.lock")

    # ---- Python
    dossiers_verrouilles = {dossier_de(c) for c in inv.verrous_python}
    dossiers_requirements = set()
    for chemin in inv.requirements:
        dossiers_requirements.add(dossier_de(chemin))
        if dossier_de(chemin) in dossiers_verrouilles:
            continue
        try:
            texte = fichiers.lire_texte(os.path.join(racine, chemin), TAILLE_MAX_MANIFESTE)
        except fichiers.LectureRefusee:
            plafonnements.append(f"{chemin} est illisible")
            continue
        if not requirements_epingle(texte):
            plafonnements.append(
                f"{chemin} ne donne pas une version exacte (==) pour chaque dépendance")
    for chemin in inv.pipfile:
        if dossier_de(chemin) not in dossiers_verrouilles:
            plafonnements.append(f"{chemin} n'a pas de Pipfile.lock")
    for chemin in inv.pyproject:
        d = dossier_de(chemin)
        if d in dossiers_verrouilles or d in dossiers_requirements:
            continue
        try:
            donnees = tomllib.loads(
                fichiers.lire_texte(os.path.join(racine, chemin), TAILLE_MAX_MANIFESTE))
        except (fichiers.LectureRefusee, tomllib.TOMLDecodeError, RecursionError):
            continue
        if _dependances_pyproject(donnees):
            avertissements.append(
                f"{affichage(chemin)} : bibliothèque Python sans fichier de verrouillage. "
                "Les versions exactes des dépendances ne sont pas connues.")

    return plafonnements, avertissements
