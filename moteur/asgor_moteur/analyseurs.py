"""Lecture des résultats de chaque outil, vers le format unique Probleme.

Chaque fonction reçoit le JSON déjà chargé. Tout ce qu'il contient vient
d'un outil qui a lu un dépôt non maîtrisé : on vérifie les types et on
limite les longueurs. Une forme inattendue lève FormatInattendu ; le moteur
marque alors l'outil comme « en échec ».
"""

import hashlib
import hmac
import re

from . import versions
from .modele import (
    CODE,
    CRITIQUE,
    DEPENDANCES,
    ELEVEE,
    FAIBLE,
    MOYENNE,
    SECRETS,
    Probleme,
    gravite_depuis_cvss,
    gravite_depuis_texte,
    masquer_secret,
    moins_grave_d_un_cran,
)

LONGUEUR_MAX_TEXTE = 2000
LONGUEUR_MAX_CHEMIN = 500


class FormatInattendu(Exception):
    pass


# ------------------------------------------------------------------ utilitaires

def _texte(valeur, longueur_max: int = LONGUEUR_MAX_TEXTE) -> str:
    if valeur is None:
        return ""
    if not isinstance(valeur, str):
        valeur = str(valeur)
    valeur = "".join(c for c in valeur if c in "\n\t" or ord(c) >= 32)
    if len(valeur) > longueur_max:
        valeur = valeur[: longueur_max - 1] + "…"
    return valeur.strip()


def _entier(valeur) -> int:
    try:
        n = int(valeur)
    except (TypeError, ValueError):
        return 0
    return n if 0 <= n < 10**9 else 0


def _chemin(valeur, racine_analyse: str = "", retirer_src: bool = True) -> str:
    """Chemin relatif à la racine du dépôt (on retire « src/ » et le dossier de l'analyse).

    retirer_src=False pour un outil qui donne déjà un chemin relatif au dépôt
    (Gitleaks en mode git) : un vrai dossier « src/ » du dépôt doit rester."""
    chemin = _texte(valeur, LONGUEUR_MAX_CHEMIN)
    if racine_analyse and chemin.startswith(racine_analyse.rstrip("/") + "/"):
        chemin = chemin[len(racine_analyse.rstrip("/")) + 1:]
    while chemin.startswith("./"):
        chemin = chemin[2:]
    if not retirer_src:
        return chemin
    if chemin == "src":
        return ""
    if chemin.startswith("src/"):
        chemin = chemin[4:]
    return chemin


def _liste(valeur) -> list:
    return valeur if isinstance(valeur, list) else []


def _dict(valeur) -> dict:
    return valeur if isinstance(valeur, dict) else {}


def _identifiants(*sources) -> list:
    ids = []
    for source in sources:
        elements = source if isinstance(source, (list, tuple)) else [source]
        for e in elements:
            if isinstance(e, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,60}", e):
                ids.append(e)
    return sorted(set(ids))


# --------------------------------------------------------------------- Gitleaks

# Nom français des types de secrets les plus courants (règles de Gitleaks).
# Les autres gardent le nom de la règle : « Secret détecté (règle xyz) ».
_TYPES_SECRETS = {
    "generic-api-key": "Clé d'API",
    "private-key": "Clé privée",
    "aws-access-token": "Clé d'accès AWS",
    "github-pat": "Jeton d'accès GitHub",
    "github-fine-grained-pat": "Jeton d'accès GitHub",
    "github-oauth": "Jeton OAuth GitHub",
    "github-app-token": "Jeton d'application GitHub",
    "gitlab-pat": "Jeton d'accès GitLab",
    "slack-bot-token": "Jeton Slack",
    "slack-webhook-url": "Adresse de webhook Slack",
    "stripe-access-token": "Clé Stripe",
    "google-api-key": "Clé d'API Google",
    "gcp-api-key": "Clé d'API Google Cloud",
    "jwt": "Jeton JWT",
    "openai-api-key": "Clé d'API OpenAI",
    "anthropic-api-key": "Clé d'API Anthropic",
    "sendgrid-api-token": "Clé SendGrid",
    "twilio-api-key": "Clé Twilio",
    "mailgun-private-api-token": "Clé Mailgun",
    "azure-ad-client-secret": "Secret client Azure AD",
    "discord-api-token": "Jeton Discord",
    "telegram-bot-api-token": "Jeton de bot Telegram",
    "npm-access-token": "Jeton npm",
    "pypi-upload-token": "Jeton PyPI",
    "hashicorp-tf-api-token": "Jeton Terraform Cloud",
    "heroku-api-key": "Clé d'API Heroku",
    "asgor-secret-tableau-php": "Secret écrit dans le code PHP",
}


def titre_secret(regle: str) -> str:
    nom = _TYPES_SECRETS.get(regle)
    if nom:
        return f"Secret détecté : {nom}"
    return f"Secret détecté (règle {regle})" if regle else "Secret détecté"


# BAREME.md § 6 b : chemins où un secret est probablement une donnée de test ou
# d'exemple. Liste propre à ASGOR : le dépôt analysé ne peut pas la modifier.
_DOSSIERS_A_VERIFIER = {"test", "tests", "spec", "fixtures", "doc", "docs",
                        "documentation", "example", "examples"}
_SUFFIXES_A_VERIFIER = (".md", ".example", ".dist", ".sample", ".min.js", ".eml")
# Noms de fichiers de test : test.js, *.test.js,
# *.spec.js, *Test.php, test_*.py, *_test.py, *_test.go
_FICHIERS_TEST = re.compile(
    r"test\.js|.+\.test\.js|.+\.spec\.js|.+Test\.php|test_.+\.py|.+_test\.py|.+_test\.go")


def chemin_a_verifier(fichier: str) -> bool:
    parties = [x.lower() for x in fichier.split("/") if x]
    if not parties:
        return False
    if any(x in _DOSSIERS_A_VERIFIER for x in parties[:-1]):
        return True
    if _FICHIERS_TEST.fullmatch(fichier.rsplit("/", 1)[-1]):
        return True
    nom = parties[-1]
    return any(nom.endswith(suffixe) or (suffixe + ".") in nom for suffixe in _SUFFIXES_A_VERIFIER)


TAILLE_MIN_CLE_EMPREINTES = 32


def empreinte_valeurs(cle: bytes, valeurs) -> str:
    """HMAC-SHA256 des valeurs distinctes d'un secret, avec la clé de l'instance.

    Un simple SHA256 se retrouverait par essais pour un secret court ou banal
    (l'identifiant est public dans le rapport) : la clé l'empêche.
    """
    texte = "\x00".join(sorted(set(valeurs)))
    return hmac.new(cle, texte.encode("utf-8", "replace"), hashlib.sha256).hexdigest()


def lire_gitleaks(donnees, *, cle: bytes) -> list:
    """Rapport JSON de Gitleaks 8 : liste de résultats.

    cle : clé de l'instance pour l'empreinte des valeurs (CLE_EMPREINTES dans
    moteur.py). L'identifiant d'un problème dépend de la règle, du fichier et des
    valeurs trouvées : une nouvelle valeur dans un fichier dont un faux positif a
    été écarté redonne un problème à examiner.

    Le secret en clair est masqué ici et n'est conservé nulle part ailleurs.
    Regroupement (BAREME.md § 6 a) : un seul problème par fichier et par type de
    secret, avec le nombre d'occurrences (lignes et commits confondus). La ligne et
    le commit gardés sont ceux de la première occurrence dans un ordre fixe, pour que
    l'identifiant et le lien « Voir sur GitHub » ne changent pas d'une analyse à l'autre.
    """
    if donnees is None:
        return []
    if not isinstance(cle, bytes) or len(cle) < TAILLE_MIN_CLE_EMPREINTES:
        raise ValueError("Gitleaks : clé d'empreinte absente ou trop courte")
    if not isinstance(donnees, list):
        raise FormatInattendu("Gitleaks : une liste était attendue")

    groupes = {}  # (règle, fichier) -> [(ligne, commit, secret masqué), ...]
    valeurs = {}  # (règle, fichier) -> {secret en clair} (en mémoire seulement)
    for r in donnees:
        r = _dict(r)
        regle = _texte(r.get("RuleID"), 100)
        secret = r.get("Secret")
        if not isinstance(secret, str):
            secret = ""
        # Gitleaks (mode git) donne le chemin relatif au dépôt, sans « src/ » du clone.
        fichier = _chemin(r.get("File"), retirer_src=False)
        ligne = _entier(r.get("StartLine"))
        commit = _texte(r.get("Commit"), 64)
        if not re.fullmatch(r"[0-9a-f]{7,64}", commit):
            commit = ""
        groupes.setdefault((regle, fichier), []).append((ligne, commit, masquer_secret(secret)))
        valeurs.setdefault((regle, fichier), set()).add(secret)

    problemes = []
    for (regle, fichier), occurrences in groupes.items():
        ligne, commit, masque = min(occurrences)
        a_verifier = chemin_a_verifier(fichier)
        problemes.append(Probleme(
            domaine=SECRETS,
            gravite=ELEVEE if a_verifier else CRITIQUE,
            titre=titre_secret(regle),
            fichier=fichier,
            ligne=ligne,
            outils=["Gitleaks"],
            regle=regle,
            explication=("Secret à vérifier : il se trouve dans un fichier de test, de documentation "
                         "ou d'exemple, et peut être une valeur factice. S'il est réel, toute personne "
                         "qui clone le dépôt peut le lire." if a_verifier else
                         "Un secret est présent dans le dépôt ou dans son historique Git. "
                         "Toute personne qui clone le dépôt peut le lire."),
            correction="révoquer ce secret et en créer un nouveau, puis le retirer du code. "
                       "Le supprimer du fichier ne suffit pas : il reste dans l'historique. "
                       "Si c'est une valeur factice, l'écarter comme faux positif.",
            commit=commit,
            secret_masque=masque,
            occurrences=len(occurrences),
            a_verifier=a_verifier,
            empreinte_valeurs=empreinte_valeurs(cle, valeurs[(regle, fichier)]),
        ))
    return problemes


# --------------------------------------------------------------- Composer Audit

def lire_composer_audit(donnees, fichier: str = "composer.lock", installees=None) -> list:
    """`composer audit --format=json` : {"advisories": {paquet: [avis...]}}.

    installees : {nom du paquet en minuscules: version}, lu dans composer.lock
    par le moteur. Composer Audit ne donne pas la version installée.
    """
    installees = installees or {}
    donnees = _dict(donnees)
    if "advisories" not in donnees:
        raise FormatInattendu("Composer Audit : clé « advisories » absente")
    avis_par_paquet = donnees["advisories"]
    if isinstance(avis_par_paquet, list):  # liste vide quand il n'y a rien
        avis_par_paquet = {}
    problemes = []
    for paquet, liste_avis in _dict(avis_par_paquet).items():
        if isinstance(liste_avis, dict):  # parfois un objet indexé par numéro
            liste_avis = list(liste_avis.values())
        for avis in _liste(liste_avis):
            avis = _dict(avis)
            ids = _identifiants(avis.get("cve"), avis.get("advisoryId"),
                                [s.get("remoteId") for s in _liste(avis.get("sources"))
                                 if isinstance(s, dict)])
            nom = _texte(avis.get("packageName") or paquet, 150)
            installee = _texte(installees.get(nom.lower(), ""), 50)
            problemes.append(Probleme(
                domaine=DEPENDANCES,
                gravite=gravite_depuis_texte(avis.get("severity")),
                titre=_texte(avis.get("title"), 200) or f"Faille connue dans {_texte(paquet, 100)}",
                fichier=fichier,
                outils=["Composer Audit"],
                regle=(ids[0] if ids else ""),
                explication=f"Versions concernées : {_texte(avis.get('affectedVersions'), 300)}",
                paquet=nom,
                version=installee,
                version_corrigee=versions.depuis_contraintes_composer(
                    installee, avis.get("affectedVersions")),
                identifiants=ids,
                references=[_texte(avis.get("link"), 300)] if avis.get("link") else [],
            ))
    return problemes


# -------------------------------------------------------------------- pip-audit

def lire_pip_audit(donnees, fichier: str = "requirements.txt") -> list:
    """`pip-audit -f json` : {"dependencies": [{"name", "version", "vulns": [...]}]}."""
    donnees = _dict(donnees)
    if "dependencies" not in donnees:
        raise FormatInattendu("pip-audit : clé « dependencies » absente")
    problemes = []
    for dep in _liste(donnees["dependencies"]):
        dep = _dict(dep)
        for vuln in _liste(dep.get("vulns")):
            vuln = _dict(vuln)
            ids = _identifiants(vuln.get("id"), _liste(vuln.get("aliases")))
            corrigees = [_texte(v, 50) for v in _liste(vuln.get("fix_versions")) if v]
            problemes.append(Probleme(
                domaine=DEPENDANCES,
                gravite=MOYENNE,  # pip-audit ne donne pas de gravité
                titre=f"Faille connue dans {_texte(dep.get('name'), 100)}",
                fichier=fichier,
                outils=["pip-audit"],
                regle=(ids[0] if ids else ""),
                explication=_texte(vuln.get("description")),
                paquet=_texte(dep.get("name"), 150),
                version=_texte(dep.get("version"), 50),
                version_corrigee=versions.plus_petite_superieure(
                    _texte(dep.get("version"), 50), corrigees),
                identifiants=ids,
            ))
    return problemes


# ------------------------------------------------------------------ OSV-Scanner

def _plages_osv(vuln: dict, paquet: str) -> list:
    """Liste de (version introduite, version corrigée) pour ce paquet."""
    plages = []
    for affecte in _liste(vuln.get("affected")):
        affecte = _dict(affecte)
        nom = _dict(affecte.get("package")).get("name")
        if isinstance(nom, str) and nom.lower() != paquet.lower():
            continue
        for plage in _liste(affecte.get("ranges")):
            introduite = ""
            for evenement in _liste(_dict(plage).get("events")):
                evenement = _dict(evenement)
                if isinstance(evenement.get("introduced"), str):
                    introduite = _texte(evenement["introduced"], 50)
                corrigee = evenement.get("fixed")
                if isinstance(corrigee, str) and corrigee:
                    plages.append((introduite, _texte(corrigee, 50)))
    return plages


def lire_osv(donnees, racine_analyse: str = "") -> list:
    """`osv-scanner --format json` : {"results": [{"source", "packages": [...]}]}."""
    donnees = _dict(donnees)
    if "results" not in donnees:
        raise FormatInattendu("OSV-Scanner : clé « results » absente")
    problemes = []
    for resultat in _liste(donnees["results"]):
        resultat = _dict(resultat)
        fichier = _chemin(_dict(resultat.get("source")).get("path"), racine_analyse)
        for entree in _liste(resultat.get("packages")):
            entree = _dict(entree)
            paquet = _dict(entree.get("package"))
            nom = _texte(paquet.get("name"), 150)

            # Score le plus élevé de chaque groupe d'identifiants.
            score_par_id = {}
            for groupe in _liste(entree.get("groups")):
                groupe = _dict(groupe)
                try:
                    score = float(groupe.get("max_severity"))
                except (TypeError, ValueError):
                    continue
                for i in _liste(groupe.get("ids")) + _liste(groupe.get("aliases")):
                    if isinstance(i, str):
                        score_par_id[i] = max(score, score_par_id.get(i, 0.0))

            for vuln in _liste(entree.get("vulnerabilities")):
                vuln = _dict(vuln)
                ids = _identifiants(vuln.get("id"), _liste(vuln.get("aliases")))
                scores = [score_par_id[i] for i in ids if i in score_par_id]
                if scores and max(scores) > 0:
                    gravite = gravite_depuis_cvss(max(scores))
                else:
                    gravite = gravite_depuis_texte(
                        _dict(vuln.get("database_specific")).get("severity"))
                version = _texte(paquet.get("version"), 50)
                problemes.append(Probleme(
                    domaine=DEPENDANCES,
                    gravite=gravite,
                    titre=_texte(vuln.get("summary"), 200) or f"Faille connue dans {nom}",
                    fichier=fichier,
                    outils=["OSV-Scanner"],
                    regle=(ids[0] if ids else ""),
                    explication=_texte(vuln.get("details")),
                    paquet=nom,
                    version=version,
                    version_corrigee=versions.depuis_plages(version, _plages_osv(vuln, nom)),
                    identifiants=ids,
                ))
    return problemes


# ------------------------------------------------------------------------ Trivy

def lire_trivy(donnees, racine_analyse: str = "") -> list:
    """`trivy fs --format json` : {"Results": [{"Target", "Vulnerabilities": [...]}]}."""
    donnees = _dict(donnees)
    if "SchemaVersion" not in donnees and "Results" not in donnees:
        raise FormatInattendu("Trivy : rapport non reconnu")
    problemes = []
    for resultat in _liste(donnees.get("Results")):
        resultat = _dict(resultat)
        fichier = _chemin(resultat.get("Target"), racine_analyse)
        for vuln in _liste(resultat.get("Vulnerabilities")):
            vuln = _dict(vuln)
            ids = _identifiants(vuln.get("VulnerabilityID"), _liste(vuln.get("VendorIDs")))
            nom = _texte(vuln.get("PkgName"), 150)
            # « FixedVersion » contient souvent une version corrigée par branche
            # (« 7.1.0, 8.1.6, 5.4.54… ») : on prend la plus petite au-dessus de
            # la version installée.
            installee = _texte(vuln.get("InstalledVersion"), 50)
            corrigee = versions.plus_petite_superieure(
                installee, [v.strip() for v in _texte(vuln.get("FixedVersion"), 1000).split(",")])
            problemes.append(Probleme(
                domaine=DEPENDANCES,
                gravite=gravite_depuis_texte(vuln.get("Severity")),
                titre=_texte(vuln.get("Title"), 200) or f"Faille connue dans {nom}",
                fichier=fichier,
                outils=["Trivy"],
                regle=(ids[0] if ids else ""),
                explication=_texte(vuln.get("Description")),
                paquet=nom,
                version=installee,
                version_corrigee=corrigee,
                identifiants=ids,
                references=[_texte(vuln.get("PrimaryURL"), 300)] if vuln.get("PrimaryURL") else [],
            ))
    return problemes


# ------------------------------------------------------------------------ Psalm

# type Psalm -> (catégorie, gravité, titre, correction)
_PSALM = {
    "TaintedSql": ("injection-sql", ELEVEE, "Injection SQL possible",
                   "utiliser une requête préparée avec des paramètres."),
    "TaintedHtml": ("xss", ELEVEE, "Affichage sans échappement (XSS possible)",
                    "échapper la valeur avant de l'afficher (htmlspecialchars, ou l'échappement du moteur de gabarits)."),
    "TaintedTextWithQuotes": ("xss", MOYENNE, "Affichage sans échappement des guillemets (XSS possible)",
                              "échapper aussi les guillemets (ENT_QUOTES)."),
    "TaintedShell": ("injection-commande", ELEVEE, "Injection de commande possible",
                     "ne pas construire de commande avec une donnée reçue ; sinon utiliser escapeshellarg."),
    "TaintedEval": ("injection-code", ELEVEE, "Exécution de code reçu (eval)",
                    "ne jamais passer une donnée reçue à eval."),
    "TaintedInclude": ("inclusion-fichier", ELEVEE, "Inclusion d'un fichier choisi par l'utilisateur",
                       "utiliser une liste fixe de fichiers autorisés."),
    "TaintedFile": ("traversee-chemin", ELEVEE, "Chemin de fichier choisi par l'utilisateur",
                    "vérifier le chemin (liste autorisée, basename, realpath)."),
    "TaintedUnserialize": ("deserialisation", ELEVEE, "Désérialisation d'une donnée reçue",
                           "utiliser JSON, ou unserialize avec allowed_classes à false."),
    "TaintedSSRF": ("ssrf", ELEVEE, "Requête vers une adresse choisie par l'utilisateur (SSRF)",
                    "utiliser une liste fixe d'adresses autorisées."),
    "TaintedCallable": ("injection-code", ELEVEE, "Fonction appelée choisie par l'utilisateur",
                        "utiliser une liste fixe de fonctions autorisées."),
    "TaintedLdap": ("injection-ldap", ELEVEE, "Injection LDAP possible",
                    "échapper la valeur avec ldap_escape."),
    "TaintedHeader": ("injection-entete", MOYENNE, "En-tête HTTP construit avec une donnée reçue",
                      "valider la valeur avant de l'utiliser dans un en-tête."),
    "TaintedCookie": ("cookie", MOYENNE, "Cookie construit avec une donnée reçue",
                      "valider la valeur avant de l'écrire dans un cookie."),
}


def lire_psalm(donnees, racine_analyse: str = "") -> list:
    """Rapport JSON de Psalm (`--report=x.json`) : liste de problèmes.

    On ne garde que les problèmes de l'analyse de flux (types « Tainted… »).
    """
    if not isinstance(donnees, list):
        raise FormatInattendu("Psalm : une liste était attendue")
    problemes = []
    for r in donnees:
        r = _dict(r)
        type_psalm = _texte(r.get("type"), 80)
        if not type_psalm.startswith("Tainted"):
            continue
        categorie, gravite, titre, correction = _PSALM.get(
            type_psalm,
            ("flux-" + type_psalm.lower(), MOYENNE,
             f"Donnée reçue utilisée sans contrôle ({type_psalm})",
             "valider ou échapper la donnée avant de l'utiliser."))
        problemes.append(Probleme(
            domaine=CODE,
            gravite=gravite,
            titre=titre,
            fichier=_chemin(r.get("file_name"), racine_analyse),
            ligne=_entier(r.get("line_from")),
            outils=["Psalm"],
            regle=type_psalm,
            explication=_texte(r.get("message")),
            correction=correction,
            categorie=categorie,
            flux=True,
            references=[_texte(r.get("link"), 300)] if r.get("link") else [],
        ))
    return problemes


# ------------------------------------------------------- Semgrep et Opengrep

_CWE_CATEGORIES = {
    89: "injection-sql", 564: "injection-sql",
    79: "xss", 80: "xss",
    77: "injection-commande", 78: "injection-commande", 88: "injection-commande",
    94: "injection-code", 95: "injection-code",
    98: "inclusion-fichier",
    22: "traversee-chemin", 23: "traversee-chemin", 73: "traversee-chemin",
    502: "deserialisation",
    918: "ssrf",
    90: "injection-ldap",
    611: "xxe",
    601: "redirection-ouverte",
    326: "crypto-faible", 327: "crypto-faible", 328: "crypto-faible",
    798: "secret-en-dur", 259: "secret-en-dur",
    352: "csrf",
}

_TITRES_CATEGORIES = {
    "injection-sql": "Injection SQL possible",
    "xss": "Affichage sans échappement (XSS possible)",
    "injection-commande": "Injection de commande possible",
    "injection-code": "Exécution de code reçu",
    "inclusion-fichier": "Inclusion d'un fichier choisi par l'utilisateur",
    "traversee-chemin": "Chemin de fichier choisi par l'utilisateur",
    "deserialisation": "Désérialisation d'une donnée reçue",
    "ssrf": "Requête vers une adresse choisie par l'utilisateur (SSRF)",
    "injection-ldap": "Injection LDAP possible",
    "xxe": "Lecture XML non protégée (XXE)",
    "redirection-ouverte": "Redirection vers une adresse choisie par l'utilisateur",
    "crypto-faible": "Chiffrement ou hachage faible",
    "secret-en-dur": "Mot de passe ou clé écrit dans le code",
    "csrf": "Protection CSRF absente",
}


def _categorie_depuis_cwe(cwes) -> str:
    if isinstance(cwes, str):
        cwes = [cwes]
    for cwe in _liste(cwes):
        m = re.match(r"\s*CWE-(\d+)", str(cwe))
        if m and int(m.group(1)) in _CWE_CATEGORIES:
            return _CWE_CATEGORIES[int(m.group(1))]
    return ""


_PREFIXE_REGLES = re.compile(r"^.*?semgrep-rules\.[A-Za-z0-9_-]+\.")


def _nom_regle(check_id: str) -> str:
    """Retire du nom de la règle le chemin d'installation des règles.

    Semgrep et Opengrep préfixent le nom par le chemin du dossier de règles,
    par exemple « opt.asgor.regles.semgrep-rules.actuel.php.lang.security.x ».
    """
    return _PREFIXE_REGLES.sub("", check_id)


def lire_semgrep(donnees, outil: str = "Semgrep", racine_analyse: str = "") -> list:
    """Sortie JSON de Semgrep ou d'Opengrep (même format) : {"results": [...]}.

    On ne garde que les règles de catégorie « security ».
    """
    donnees = _dict(donnees)
    if "results" not in donnees:
        raise FormatInattendu(f"{outil} : clé « results » absente")
    problemes = []
    for r in _liste(donnees["results"]):
        r = _dict(r)
        extra = _dict(r.get("extra"))
        meta = _dict(extra.get("metadata"))
        if _texte(meta.get("category"), 40).lower() != "security":
            continue
        gravite = {
            "CRITICAL": ELEVEE, "ERROR": ELEVEE, "HIGH": ELEVEE,
            "WARNING": MOYENNE, "MEDIUM": MOYENNE,
            "INFO": FAIBLE, "LOW": FAIBLE,
        }.get(_texte(extra.get("severity"), 20).upper(), MOYENNE)
        if _texte(meta.get("confidence"), 20).upper() == "LOW":
            gravite = moins_grave_d_un_cran(gravite)
        regle = _nom_regle(_texte(r.get("check_id"), 300))
        categorie = _categorie_depuis_cwe(meta.get("cwe"))
        titre = _TITRES_CATEGORIES.get(categorie) or regle.rsplit(".", 1)[-1].replace("-", " ")
        references = [_texte(x, 300) for x in _liste(meta.get("references"))[:3]]
        problemes.append(Probleme(
            domaine=CODE,
            gravite=gravite,
            titre=titre,
            fichier=_chemin(r.get("path"), racine_analyse),
            ligne=_entier(_dict(r.get("start")).get("line")),
            outils=[outil],
            regle=regle,
            explication=_texte(extra.get("message")),
            categorie=categorie,
            references=references,
        ))
    return problemes


# ----------------------------------------------------------------------- Bandit

# Règles dont le texte (issue_text) contient la valeur trouvée, par exemple
# « Possible hardcoded password: 'xxx' » (vérifié avec Bandit 1.9.4 le 18/11/2026).
# Ce texte n'est jamais repris : il irait en clair dans la page, le JSON et le SARIF.
_TEXTES_BANDIT_MAITRISES = {
    "B105": "Mot de passe probablement écrit en dur dans une chaîne du code.",
    "B106": "Mot de passe probablement écrit en dur dans un argument d'appel de fonction.",
    "B107": "Mot de passe probablement écrit en dur comme valeur par défaut d'un argument.",
}


def lire_bandit(donnees, racine_analyse: str = "") -> list:
    """`bandit -f json` : {"results": [{"filename", "line_number", "test_id", ...}]}."""
    donnees = _dict(donnees)
    if "results" not in donnees:
        raise FormatInattendu("Bandit : clé « results » absente")
    problemes = []
    for r in _liste(donnees["results"]):
        r = _dict(r)
        gravite = gravite_depuis_texte(r.get("issue_severity"), FAIBLE)
        if _texte(r.get("issue_confidence"), 20).upper() == "LOW":
            gravite = moins_grave_d_un_cran(gravite)
        cwe = _dict(r.get("issue_cwe")).get("id")
        categorie = _categorie_depuis_cwe([f"CWE-{cwe}"]) if cwe else ""
        test_id = _texte(r.get("test_id"), 20)
        nom = _texte(r.get("test_name"), 80)
        problemes.append(Probleme(
            domaine=CODE,
            gravite=gravite,
            titre=_TITRES_CATEGORIES.get(categorie) or nom.replace("_", " ") or test_id,
            fichier=_chemin(r.get("filename"), racine_analyse),
            ligne=_entier(r.get("line_number")),
            outils=["Bandit"],
            regle=f"{test_id} {nom}".strip(),
            explication=_TEXTES_BANDIT_MAITRISES.get(test_id.upper()) or _texte(r.get("issue_text")),
            categorie=categorie,
            references=[_texte(r.get("more_info"), 300)] if r.get("more_info") else [],
        ))
    return problemes


NB_MAX_FICHIERS_NON_LUS = 500


def erreurs_bandit(donnees, racine_analyse: str = "") -> list:
    """Fichiers que Bandit n'a pas pu analyser (clé « errors » de son JSON).

    Bandit les signale à part et continue : sans cette lecture, un fichier manqué
    disparaissait du bilan. Renvoie ["chemin (Bandit : raison)", ...]."""
    resultat = []
    for e in _liste(_dict(donnees).get("errors"))[:NB_MAX_FICHIERS_NON_LUS]:
        e = _dict(e)
        chemin = _chemin(e.get("filename"), racine_analyse) or "fichier inconnu"
        raison = _texte(e.get("reason"), 120) or "erreur d'analyse"
        resultat.append(f"{chemin} (Bandit : {raison})")
    return resultat


# ---------------------------------------------------------------------- PHPStan

NB_MAX_ERREURS_QUALITE = 200


def lire_phpstan(donnees, racine_analyse: str = "", niveau: int = 0) -> dict:
    """`phpstan analyse --error-format=json` : rubrique « Qualité du code ».

    Ces résultats ne sont pas des Probleme et n'ont aucun effet sur la note.
    """
    donnees = _dict(donnees)
    if "totals" not in donnees or "files" not in donnees:
        raise FormatInattendu("PHPStan : clés « totals » et « files » attendues")
    erreurs = []
    par_type = {}
    par_fichier = {}
    fichiers_phpstan = donnees["files"]
    if isinstance(fichiers_phpstan, list):  # liste vide quand il n'y a rien
        fichiers_phpstan = {}
    for chemin, contenu in _dict(fichiers_phpstan).items():
        fichier = _chemin(chemin, racine_analyse)
        for message in _liste(_dict(contenu).get("messages")):
            message = _dict(message)
            identifiant = _texte(message.get("identifier"), 80) or "autre"
            par_type[identifiant] = par_type.get(identifiant, 0) + 1
            par_fichier[fichier] = par_fichier.get(fichier, 0) + 1
            erreurs.append({
                "fichier": fichier,
                "ligne": _entier(message.get("line")),
                "type": identifiant,
                "message": _texte(message.get("message"), 500),
            })
    erreurs.sort(key=lambda e: (e["fichier"], e["ligne"]))
    generales = [_texte(e, 300) for e in _liste(donnees.get("errors"))[:20]]
    trier = lambda d: [{"nom": k, "nombre": v}  # noqa: E731
                       for k, v in sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))]
    return {
        "outil": "PHPStan",
        "niveau": niveau,
        "effet_sur_la_note": "aucun",
        "nb_erreurs": len(erreurs),
        "nb_fichiers": len(par_fichier),
        "par_type": trier(par_type)[:30],
        "par_fichier": trier(par_fichier)[:30],
        "erreurs": erreurs[:NB_MAX_ERREURS_QUALITE],
        "erreurs_tronquees": len(erreurs) > NB_MAX_ERREURS_QUALITE,
        "erreurs_generales": generales,
    }
