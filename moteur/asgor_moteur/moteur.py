"""Enchaînement des étapes d'une analyse ASGOR.

À lancer en root sur la VM. Chaque outil passe par asgor-sandbox :
profil « fetch » (Internet seulement) ou « scan » (aucun réseau).
Le moteur lui-même ne lance aucun outil hors de l'isolation et n'exécute
aucun code du dépôt analysé.
"""

import datetime
import fcntl
import grp
import json
import pwd
import os
import re
import secrets
import shutil
import time

from . import analyseurs, avancement, fichiers, sarif
from .avancement import Observateur, nombre_fr
from .depot import inventorier, requirements_epingle, verifier_verrouillage
from .etapes import ANNULEE, DELAI, ECHEC, OK, Lanceur, LanceurDocker
from .fusion import supprimer_doublons
from .modele import CODE, DEPENDANCES, MOYENNE, SECRETS, Probleme
from .notation import Contexte, noter
from .url import Depot

VERSION_MOTEUR = "0.2"
VERSION_FORMAT = 3   # 3 : état de chaque domaine, score null si non noté

DONNEES = "/var/lib/asgor"
ANALYSES = f"{DONNEES}/jobs"
RAPPORTS = f"{DONNEES}/reports"
JOURNAUX = f"{DONNEES}/logs"
CACHE_OSV = f"{DONNEES}/cache/osv"
CONF = "/opt/asgor/moteur/conf"
REGLES = "/opt/asgor/regles/semgrep-rules/actuel"
VERROU = "/run/asgor-scan.lock"
OUTILS = "/opt/asgor/outils.json"      # versions des outils, écrit par le playbook
# Clé de l'empreinte des secrets (HMAC), créée par le playbook, 0600 root.
# Dans /etc/asgor/secrets/, invisible depuis les analyses.
CLE_EMPREINTES = "/etc/asgor/secrets/empreintes.key"
GROUPE_WEB = "asgor-web"                # le service web lit les rapports (étape 4)

TAILLE_MAX_DEPOT = 500 * 1024 * 1024   # règle 4 de sécurité du moteur (README.md)
DUREE_MAX_ANALYSE = 30 * 60


def mode_docker() -> bool:
    """Image Docker : étapes lancées par le filtre du socket Docker (LanceurDocker)."""
    return os.environ.get("ASGOR_LANCEUR") == "docker"
NB_MAX_AUDITS = 5
NIVEAU_PHPSTAN = 5  # 0 à 10 ; rubrique « Qualité du code », sans effet sur la note

EXCLUS = ("vendor", "node_modules", ".git", ".venv", "venv")


class AnalyseImpossible(Exception):
    """L'analyse ne peut pas commencer ou continuer (dépôt refusé, clonage en échec…)."""


class AnalyseEnCours(Exception):
    """Une autre analyse tourne déjà (une seule à la fois)."""


class AnalyseAnnulee(Exception):
    """L'utilisateur a demandé l'annulation."""


class AnalyseExistante(Exception):
    """Ce commit a déjà été analysé récemment (le worker renvoie vers ce rapport)."""

    def __init__(self, commit: str):
        super().__init__(f"commit {commit} déjà analysé récemment")
        self.commit = commit


_IDENTIFIANT = re.compile(r"[0-9a-f]{32}")


def nouvel_identifiant() -> str:
    """32 caractères hexadécimaux tirés au hasard : impossible à deviner.

    C'est l'adresse permanente du rapport.
    """
    return secrets.token_hex(16)


def identifiant_valide(identifiant) -> bool:
    return isinstance(identifiant, str) and _IDENTIFIANT.fullmatch(identifiant) is not None


# Étape du moteur (début du nom) -> outil de outils.json
OUTIL_PAR_ETAPE = (
    ("gitleaks", "Gitleaks"),
    ("composer-", "Composer"),
    ("pip-audit", "pip-audit"),
    ("base-osv", "OSV-Scanner"), ("osv-scanner", "OSV-Scanner"),
    ("base-trivy", "Trivy"), ("trivy", "Trivy"),
    ("psalm", "Psalm"),
    ("phpstan", "PHPStan"),
    ("opengrep", "Opengrep"),
    ("bandit", "Bandit"),
)


def outils_lances(etapes) -> set:
    """Outils dont au moins une étape a vraiment tourné (réussie ou non)."""
    lances = set()
    for etape in etapes:
        if etape.statut in (OK, ECHEC, DELAI):
            for prefixe, outil in OUTIL_PAR_ETAPE:
                if etape.nom.startswith(prefixe):
                    lances.add(outil)
    return lances


def versions_des_outils(chemin: str | None = None) -> dict:
    """{outil: version} écrit par le playbook. Vide si le fichier manque."""
    chemin = chemin or OUTILS
    try:
        donnees = fichiers.lire_json(chemin, 100_000)
    except fichiers.LectureRefusee:
        return {}
    if not isinstance(donnees, dict):
        return {}
    return {str(k)[:40]: str(v)[:60] for k, v in list(donnees.items())[:40]
            if isinstance(k, str) and isinstance(v, str)}


def _psalm_xml(inv) -> str:
    ignores = "".join(
        f'      <directory name="src/{_xml(d)}"/>\n' for d in inv.dossiers_tiers[:100])
    bloc_ignores = f"    <ignoreFiles>\n{ignores}    </ignoreFiles>\n" if ignores else ""
    # Les dépendances installées (un dossier vendor par composer.lock dans un
    # monorepo) sont lues pour connaître les classes, mais pas analysées.
    vendors = [d for d in inv.dossiers_tiers if os.path.basename(d) == "vendor"][:20]
    extra = ""
    if vendors:
        lignes = "".join(f'    <directory name="src/{_xml(d)}"/>\n' for d in vendors)
        extra = f"  <extraFiles>\n{lignes}  </extraFiles>\n"
    return (
        '<?xml version="1.0"?>\n'
        '<!-- Généré par ASGOR. La configuration du dépôt analysé n\'est jamais utilisée. -->\n'
        '<psalm errorLevel="8" resolveFromConfigFile="true"\n'
        '       xmlns="https://getpsalm.org/schema/config">\n'
        '  <projectFiles>\n'
        '    <directory name="src"/>\n'
        f'{bloc_ignores}'
        '  </projectFiles>\n'
        f'{extra}'
        '</psalm>\n'
    )


# Message de Composer quand composer.lock ne correspond plus à composer.json.
_LOCK_PERIME = "The lock file is not up to date with the latest changes in composer.json"


def lock_perime(journal: str) -> bool:
    """Vrai si le journal de « composer install » signale un composer.lock périmé."""
    if not journal:
        return False
    try:
        texte = fichiers.lire_texte(journal, 2 * 1024 * 1024)
    except fichiers.LectureRefusee:
        return False
    return _LOCK_PERIME in texte


def probleme_lock_perime(verrou: str) -> Probleme:
    """composer.lock périmé : problème de dépendances de gravité moyenne."""
    return Probleme(
        domaine=DEPENDANCES,
        gravite=MOYENNE,
        titre="composer.lock ne correspond plus à composer.json",
        fichier=verrou,
        outils=["Composer"],
        regle="composer-lock-perime",
        explication="Les versions fixées dans composer.lock ne respectent plus les contraintes "
                    "de composer.json. On ne sait pas quelles versions sont réellement "
                    "installées, et l'analyse des dépendances de ce dossier n'est pas fiable.",
        correction="lancer composer update dans ce dossier, vérifier les tests, puis "
                   "committer le nouveau composer.lock.",
    )


def _phpstan_neon(inv) -> str:
    """Configuration PHPStan générée par ASGOR. Celle du dépôt n'est jamais lue.

    Pas de bootstrapFiles, pas d'includes, pas d'extension : rien qui charge du
    code. Les dossiers vendor sont lus pour connaître les classes, mais pas
    analysés (excludePaths.analyse) ; node_modules et autres sont ignorés.
    """
    tiers = inv.dossiers_tiers[:100]
    vendors = [d for d in tiers if os.path.basename(d) == "vendor"]
    autres = [d for d in tiers if os.path.basename(d) != "vendor"]

    def liste(chemins):
        return "".join(f"            - src/{_neon(d)}\n" for d in chemins)

    exclusions = ""
    if vendors or autres:
        exclusions = "    excludePaths:\n"
        if vendors:
            exclusions += "        analyse:\n" + liste(vendors)
        if autres:
            exclusions += "        analyseAndScan:\n" + liste(autres)
    return (
        "# Généré par ASGOR. La configuration du dépôt analysé n'est jamais utilisée.\n"
        "parameters:\n"
        f"    level: {NIVEAU_PHPSTAN}\n"
        "    paths:\n"
        "        - src\n"
        "    tmpDir: home/phpstan\n"
        + exclusions
    )


def _neon(chemin: str) -> str:
    """Chemin sûr dans un fichier NEON : on refuse tout caractère spécial."""
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,300}", chemin):
        raise AnalyseImpossible(f"chemin inattendu pour PHPStan : {chemin!r}")
    return chemin


def _xml(texte: str) -> str:
    return (texte.replace("&", "&amp;").replace('"', "&quot;")
            .replace("<", "&lt;").replace(">", "&gt;"))


class Analyse:
    """Une analyse. Paramètres :

    - id_analyse : 32 hex fournis par le service web ; tiré au hasard si absent ;
    - historique_complet : faux = clone du dernier commit seulement (note B au maximum) ;
    - observateur : reçoit l'avancement par groupes (avancement.py) ;
    - arret() -> bool : vrai quand l'annulation est demandée ;
    - doublon(commit) -> bool : vrai si ce commit a déjà été analysé récemment ;
      l'analyse s'arrête alors avant le clonage (AnalyseExistante).
    """

    def __init__(self, depot: Depot, garder_sources: bool = False, afficher=print,
                 id_analyse: str | None = None, historique_complet: bool = True,
                 observateur: Observateur | None = None, arret=None, doublon=None):
        if id_analyse is not None and not identifiant_valide(id_analyse):
            raise AnalyseImpossible("identifiant d'analyse invalide")
        self.depot = depot
        self.garder_sources = garder_sources
        self.afficher = afficher
        self.historique_complet = bool(historique_complet)
        self.observateur = observateur or Observateur()
        self.arret = arret
        self.doublon = doublon
        self.id = id_analyse or nouvel_identifiant()
        self.dossier = os.path.join(ANALYSES, self.id)
        self.src = os.path.join(self.dossier, "src")
        self.out = os.path.join(self.dossier, "out")
        self.journaux = os.path.join(JOURNAUX, self.id)
        self.problemes = []
        self.avertissements = []
        self.contexte = Contexte(outils_reussis={})
        self.qualite = None
        self.infos_depot = {}
        self.lanceur = None
        self.chemin_rapport = None
        self.chemin_sarif = None
        self._detail = ""
        self._statut_groupe = None

    # ------------------------------------------------------------ utilitaires

    def _etape(self, nom, profil, commande, **options):
        self.afficher(f"  [{profil:5}] {nom} …")
        etape = self.lanceur.lancer(nom, profil, commande, **options)
        memoire = (f", {etape.memoire_max_octets // (1024 * 1024)} Mo"
                   if etape.memoire_max_octets else "")
        self.afficher(f"          {etape.statut} ({etape.duree_s:.0f} s{memoire})")
        if etape.statut == ANNULEE:
            raise AnalyseAnnulee()
        return etape

    def _nb_echecs(self) -> int:
        return sum(len(v) for v in self.contexte.outils_en_echec.values())

    def _groupe(self, cle: str, fonction, *arguments):
        """Lance un groupe d'étapes et prévient l'observateur."""
        self.observateur.groupe_commence(cle)
        debut = time.monotonic()
        echecs_avant = self._nb_echecs()
        self._detail, self._statut_groupe = "", None
        try:
            resultat = fonction(*arguments)
        except AnalyseAnnulee:
            self.observateur.groupe_termine(cle, avancement.ANNULEE, "",
                                            time.monotonic() - debut)
            raise
        except AnalyseExistante:
            self.observateur.groupe_termine(cle, avancement.TERMINEE, "commit déjà analysé",
                                            time.monotonic() - debut)
            raise
        except AnalyseImpossible as e:
            self.observateur.groupe_termine(cle, avancement.ECHEC, str(e),
                                            time.monotonic() - debut)
            raise
        statut = self._statut_groupe or (
            avancement.ECHEC if self._nb_echecs() > echecs_avant else avancement.TERMINEE)
        self.observateur.groupe_termine(cle, statut, self._detail, time.monotonic() - debut)
        return resultat

    def _groupe_ignore(self, cle: str, raison: str) -> None:
        self.observateur.groupe_termine(cle, avancement.IGNOREE, raison, 0.0)

    def _outils_reussis(self, debut_etapes: int, noms: dict) -> str:
        """Noms des outils dont au moins une étape a réussi depuis debut_etapes."""
        vus = []
        for etape in self.lanceur.etapes[debut_etapes:]:
            for prefixe, nom in noms.items():
                if etape.nom.startswith(prefixe) and etape.statut == OK and nom not in vus:
                    vus.append(nom)
        return ", ".join(vus)

    def _echec_outil(self, domaine: str, outil: str, raison: str) -> None:
        self.contexte.outils_en_echec.setdefault(domaine, [])
        if outil not in self.contexte.outils_en_echec[domaine]:
            self.contexte.outils_en_echec[domaine].append(outil)
        self.contexte.raisons_echec.setdefault(outil, raison)   # la première cause
        self.avertissements.append(f"{outil} n'a pas donné de résultat : {raison}")

    def _outil_reussi(self, domaine: str, outil: str) -> None:
        reussis = self.contexte.outils_reussis.setdefault(domaine, [])
        if outil not in reussis:
            reussis.append(outil)

    def _lire_resultat(self, etape, domaine, nom_outil, nom_sortie, lecteur, /, **options) -> None:
        """Lit le fichier de résultat d'un outil et ajoute ses problèmes."""
        if etape.statut == DELAI:
            self._echec_outil(domaine, nom_outil, "délai dépassé")
            return
        if etape.statut == ECHEC:
            self._echec_outil(domaine, nom_outil, etape.detail)
            return
        try:
            donnees = fichiers.lire_json(os.path.join(self.out, nom_sortie))
            self.problemes.extend(lecteur(donnees, **options))
        except (fichiers.LectureRefusee, analyseurs.FormatInattendu) as e:
            self._echec_outil(domaine, nom_outil, str(e))
            return None
        self._outil_reussi(domaine, nom_outil)
        return donnees

    def _versions_composer(self, verrou: str) -> dict:
        """{nom en minuscules: version} lu dans composer.lock (lecture JSON seule).

        Composer Audit ne donne pas la version installée : il en faut une pour
        choisir la bonne version corrigée.
        """
        try:
            donnees = fichiers.lire_json(os.path.join(self.src, verrou), 50 * 1024 * 1024)
        except fichiers.LectureRefusee:
            return {}
        if not isinstance(donnees, dict):
            return {}
        installees = {}
        for cle in ("packages", "packages-dev"):
            paquets = donnees.get(cle)
            if not isinstance(paquets, list):
                continue
            for paquet in paquets:
                if not isinstance(paquet, dict):
                    continue
                nom, version = paquet.get("name"), paquet.get("version")
                if isinstance(nom, str) and isinstance(version, str) and len(nom) <= 150:
                    installees[nom.lower()] = version[:50]
        return installees

    def _sortie_texte(self, nom: str, motif: str) -> str:
        try:
            texte = fichiers.lire_texte(os.path.join(self.out, nom), 1000).strip()
        except fichiers.LectureRefusee:
            return ""
        return texte if re.fullmatch(motif, texte) else ""

    # ----------------------------------------------------------------- étapes

    def _verifier_depot(self) -> None:
        etape = self._etape("verification-depot", "fetch", [
            "curl", "--silent", "--show-error", "--fail", "--proto", "=https",
            "--max-redirs", "0", "--max-time", "30", "--max-filesize", "2000000",
            "-H", "Accept: application/vnd.github+json", "-H", "User-Agent: asgor",
            "-o", "out/depot.json", self.depot.url_api], duree_max=60)
        if etape.statut != OK:
            raise AnalyseImpossible(
                "GitHub ne décrit pas ce dépôt : il est introuvable, privé, renommé, "
                "ou la limite de requêtes de l'API est atteinte.")
        try:
            infos = fichiers.lire_json(os.path.join(self.out, "depot.json"), 2_000_000)
        except fichiers.LectureRefusee as e:
            raise AnalyseImpossible(f"réponse de GitHub illisible : {e}") from e
        if not isinstance(infos, dict) or infos.get("private") is not False:
            raise AnalyseImpossible("ce dépôt n'est pas public")
        taille_ko = infos.get("size")
        if not isinstance(taille_ko, int) or taille_ko < 0:
            raise AnalyseImpossible("taille du dépôt inconnue")
        if taille_ko * 1024 > TAILLE_MAX_DEPOT:
            raise AnalyseImpossible(
                f"dépôt trop gros : {taille_ko // 1024} Mo (limite : "
                f"{TAILLE_MAX_DEPOT // (1024 * 1024)} Mo)")
        self.infos_depot["taille_annoncee_ko"] = taille_ko

    def _commit_distant(self) -> None:
        """Lit le commit de la branche principale avant de cloner.

        Si ce commit a déjà été analysé récemment, l'analyse s'arrête ici.
        """
        etape = self._etape("commit-distant", "fetch", [
            "sh", "-c",
            'exec git -c http.followRedirects=false -c protocol.file.allow=never '
            'ls-remote "$1" HEAD > out/ls-remote.txt',
            "sh", self.depot.url_clonage], duree_max=60)
        if etape.statut != OK:
            raise AnalyseImpossible("impossible de lire le dernier commit du dépôt sur GitHub")
        try:
            texte = fichiers.lire_texte(os.path.join(self.out, "ls-remote.txt"), 10_000)
        except fichiers.LectureRefusee as e:
            raise AnalyseImpossible(f"réponse de git illisible : {e}") from e
        m = re.match(r"([0-9a-f]{40}|[0-9a-f]{64})\tHEAD\b", texte)
        if not m:
            raise AnalyseImpossible("dernier commit du dépôt introuvable (dépôt vide ?)")
        self.infos_depot["commit_distant"] = m.group(1)
        if self.doublon is not None and self.doublon(m.group(1)):
            raise AnalyseExistante(m.group(1))

    def _cloner(self) -> None:
        # Case « Analyser l'historique de la branche par défaut » décochée : dernier commit
        # seulement. Cochée : historique de la branche par défaut (--single-branch) ; les
        # commits propres aux autres branches ne sont pas clonés.
        # Gitleaks (mode git) ne voit alors que les fichiers actuels (vérifié :
        # git log -p d'un clone --depth 1 montre les fichiers actuels
        # comme ajoutés, pas les fichiers supprimés plus tôt).
        profondeur = [] if self.historique_complet else ["--depth", "1"]
        etape = self._etape("clonage", "fetch", [
            "git", "-c", "http.followRedirects=false", "-c", "core.symlinks=false",
            "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
            "clone", "--quiet", "--no-recurse-submodules", "--single-branch", "--no-tags",
            *profondeur, self.depot.url_clonage, "src"], duree_max=900)
        if etape.statut != OK:
            raise AnalyseImpossible(f"le clonage a échoué ({etape.statut})")
        taille = fichiers.taille_dossier(self.src, TAILLE_MAX_DEPOT)
        if taille > TAILLE_MAX_DEPOT:
            raise AnalyseImpossible(
                f"dépôt trop gros une fois cloné (limite : "
                f"{TAILLE_MAX_DEPOT // (1024 * 1024)} Mo)")
        self.infos_depot["taille_octets"] = taille

        self._etape("informations-git", "scan", [
            "sh", "-c",
            "git -C src rev-parse HEAD > out/commit.txt; "
            "git -C src rev-list --count HEAD > out/nb-commits.txt; "
            "git -C src rev-parse --abbrev-ref HEAD > out/branche.txt"], duree_max=120)
        self.infos_depot["commit"] = self._sortie_texte("commit.txt", r"[0-9a-f]{40,64}")
        self.infos_depot["nb_commits"] = int(self._sortie_texte("nb-commits.txt", r"[0-9]{1,9}") or 0)
        self.infos_depot["branche"] = self._sortie_texte("branche.txt", r"[A-Za-z0-9._/-]{1,100}")
        self.observateur.depot_connu(self.infos_depot["commit"], self.infos_depot["branche"],
                                     self.infos_depot["nb_commits"])
        taille_mo = max(1, round(taille / (1024 * 1024)))
        if self.historique_complet:
            self._detail = f"{nombre_fr(self.infos_depot['nb_commits'])} commits, {taille_mo} Mo"
        else:
            self._detail = f"dernier commit seulement (historique non analysé), {taille_mo} Mo"

    def _clonage(self) -> None:
        self._verifier_depot()
        self._commit_distant()
        self._cloner()

    def _langages(self):
        inv = inventorier(self.src)
        if inv.tronque:
            self.avertissements.append(
                "Le dépôt contient trop de fichiers : l'inventaire est partiel.")
        plafonds, avertissements = verifier_verrouillage(self.src, inv)
        self.contexte.sans_verrouillage = plafonds
        self.avertissements.extend(avertissements)
        self._detail = ", ".join(inv.langages) or "ni PHP ni Python"
        self._perimetre(inv)
        return inv

    def _perimetre(self, inv) -> None:
        """Domaines sans rien à analyser, et code non analysé (BAREME.md § 3 b).

        Inventaire tronqué : on ne déclare rien « hors périmètre » (dans le doute,
        le domaine est évalué)."""
        autres = ", ".join(f"{langage} : {nombre_fr(n)} fichier{'s' if n > 1 else ''}"
                           for langage, n in sorted(inv.non_pris_en_charge.items(),
                                                    key=lambda e: (-e[1], e[0])))
        if inv.tronque:
            return
        if not (inv.php or inv.python):
            raison = "aucun fichier PHP ou Python"
            if autres:
                raison += f" ; {autres}, langage non pris en charge par ASGOR"
            self.contexte.hors_perimetre[CODE] = raison
        elif autres:
            self.avertissements.append(
                f"Fichiers de code non analysés (langage non pris en charge par ASGOR) : {autres}.")
        if not inv.fichiers_dependances:
            self.contexte.hors_perimetre[DEPENDANCES] = (
                "aucun fichier de dépendances (composer.json, requirements.txt, package.json…)")

    def _mettre_a_jour_les_bases(self) -> None:
        self._base_trivy = self._etape("base-trivy", "fetch", [
            "trivy", "fs", "--download-db-only", "--no-progress", "--skip-version-check",
            "--disable-telemetry", "--config", f"{CONF}/trivy.yaml"], duree_max=600)
        self._base_osv = self._etape("base-osv", "fetch", [
            "env", f"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY={CACHE_OSV}",
            "osv-scanner", "scan", "source", "--download-offline-databases",
            "--offline-vulnerabilities", "--recursive", "--no-ignore", "--allow-no-lockfiles",
            "--config", f"{CONF}/osv-scanner.toml", "--format", "json",
            "--output-file", "out/osv-telechargement.json", "src"],
            duree_max=600, codes_ok=(0, 1))

    def _copie_pour_composer_audit(self, verrou: str, n: int) -> str:
        """Copie de composer.lock avec un composer.json vide écrit par ASGOR.

        Composer Audit obéit à la section « config.audit » du composer.json du dépôt
        (ignore, ignore-severity) : un dépôt pouvait masquer toutes ses failles
        (vérifié le 16/11/2026 : 14 avis sans cette section, 0 avec). Le composer.json
        du dépôt n'est donc jamais lu par Composer Audit.
        """
        relatif = f"out/composer-audit-{n}"
        dossier = os.path.join(self.dossier, relatif)
        os.makedirs(dossier, mode=0o700)
        verrou_brut = fichiers.lire_octets(os.path.join(self.src, verrou), 50 * 1024 * 1024)
        with open(os.path.join(dossier, "composer.lock"), "wb") as f:
            f.write(verrou_brut)
        fichiers.ecrire_nouveau(os.path.join(dossier, "composer.json"), "{}\n", 0o600)
        try:
            compte = pwd.getpwnam("asgor")
        except KeyError:
            compte = None   # tests sur le Mac
        if compte is not None:
            for chemin in (dossier, os.path.join(dossier, "composer.lock"),
                           os.path.join(dossier, "composer.json")):
                os.chown(chemin, compte.pw_uid, compte.pw_gid)
        return relatif

    def _audits_en_ligne(self, inv) -> None:
        for n, verrou in enumerate(inv.composer_lock[:NB_MAX_AUDITS], 1):
            try:
                dossier = self._copie_pour_composer_audit(verrou, n)
            except (fichiers.LectureRefusee, OSError) as e:
                self._echec_outil(DEPENDANCES, "Composer Audit", f"{verrou} illisible ({e})")
                continue
            sortie = f"composer-audit-{n}.json"
            etape = self._etape(f"composer-audit-{n}", "fetch", [
                "sh", "-c",
                'exec composer audit --locked --format=json --no-plugins --no-scripts '
                '--no-interaction -d "$1" > "$2"',
                "sh", dossier, f"out/{sortie}"], duree_max=300, codes_ok=(0, 1, 2, 3))
            self._lire_resultat(etape, DEPENDANCES, "Composer Audit", sortie,
                                analyseurs.lire_composer_audit, fichier=verrou,
                                installees=self._versions_composer(verrou))

        epingles = []
        for chemin in inv.requirements:
            try:
                texte = fichiers.lire_texte(os.path.join(self.src, chemin), 2_000_000)
            except fichiers.LectureRefusee:
                continue
            if requirements_epingle(texte):
                epingles.append(chemin)
        for n, chemin in enumerate(epingles[:NB_MAX_AUDITS], 1):
            sortie = f"pip-audit-{n}.json"
            etape = self._etape(f"pip-audit-{n}", "fetch", [
                "pip-audit", "-r", os.path.join("src", chemin), "--no-deps", "--disable-pip",
                "-f", "json", "-o", f"out/{sortie}"], duree_max=300, codes_ok=(0, 1))
            self._lire_resultat(etape, DEPENDANCES, "pip-audit", sortie,
                                analyseurs.lire_pip_audit, fichier=chemin)

    def _neutraliser_gitleaksignore(self) -> None:
        """Supprime le .gitleaksignore de la copie du dépôt avant Gitleaks.

        Gitleaks lit le .gitleaksignore à la racine du dépôt analysé même quand on
        lui passe un autre fichier avec --gitleaks-ignore-path (vérifié le 16/11/2026
        avec le dépôt piège : 2 secrets trouvés sur 4). Il lit les secrets dans
        l'historique Git, pas dans ce fichier : le supprimer de la copie ne change
        rien d'autre. Le dépôt d'origine n'est pas touché.
        """
        chemin = os.path.join(self.src, ".gitleaksignore")
        if not os.path.lexists(chemin):
            return
        if os.path.isdir(chemin) and not os.path.islink(chemin):
            shutil.rmtree(chemin, ignore_errors=True)   # « dossier contenant un .gitleaksignore »
        else:
            fichiers.supprimer(chemin)                   # ne suit pas un lien symbolique
        self.avertissements.append(
            "Le dépôt contient un fichier .gitleaksignore : ASGOR l'ignore, car il peut "
            "masquer des secrets.")

    def _cle_empreintes(self):
        """Clé de l'empreinte des secrets, ou None si absente ou trop courte."""
        try:
            cle = fichiers.lire_octets(CLE_EMPREINTES, 4096)
        except fichiers.LectureRefusee:
            return None
        return cle if len(cle) >= analyseurs.TAILLE_MIN_CLE_EMPREINTES else None

    def _secrets(self) -> None:
        self._neutraliser_gitleaksignore()
        cle = self._cle_empreintes()
        brut = "gitleaks.json"
        etape = self._etape("gitleaks", "scan", [
            "gitleaks", "git", "src", "--config", f"{CONF}/gitleaks.toml",
            "--gitleaks-ignore-path", f"{CONF}/gitleaksignore", "--ignore-gitleaks-allow",
            "--report-format", "json", "--report-path", f"out/{brut}",
            "--no-banner", "--exit-code", "0", "--log-level", "warn"], duree_max=1200)
        try:
            if cle is None:
                # Sans clé, l'identifiant d'un secret se retrouverait par essais.
                self._echec_outil(SECRETS, "Gitleaks", "clé d'empreinte des secrets absente "
                                  f"ou trop courte ({CLE_EMPREINTES}) : relancer le playbook")
            else:
                self._lire_resultat(etape, SECRETS, "Gitleaks", brut, analyseurs.lire_gitleaks,
                                    cle=cle)
        finally:
            # Le rapport brut contient les secrets en clair : on ne le garde pas.
            fichiers.supprimer(os.path.join(self.out, brut))
        n = sum(1 for p in self.problemes if p.domaine == SECRETS)
        portee = "historique de la branche par défaut" if self.historique_complet else "fichiers actuels"
        self._detail = (f"Gitleaks, {portee} — "
                        + (f"{n} secret{'s' if n > 1 else ''} détecté{'s' if n > 1 else ''}"
                           if n else "aucun secret"))

    def _dependances(self, inv) -> None:
        debut = len(self.lanceur.etapes)
        self._mettre_a_jour_les_bases()
        self._audits_en_ligne(inv)
        self._dependances_hors_ligne()
        self._detail = self._outils_reussis(debut, {
            "composer-audit": "Composer Audit", "pip-audit": "pip-audit",
            "osv-scanner": "OSV-Scanner", "trivy": "Trivy"})

    def _dependances_hors_ligne(self) -> None:
        if self._base_osv.statut == OK:
            etape = self._etape("osv-scanner", "scan", [
                "env", f"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY={CACHE_OSV}",
                "osv-scanner", "scan", "source", "--offline-vulnerabilities", "--recursive",
                "--no-ignore", "--allow-no-lockfiles",
                "--config", f"{CONF}/osv-scanner.toml", "--format", "json",
                "--output-file", "out/osv.json", "src"], duree_max=600, codes_ok=(0, 1))
            self._lire_resultat(etape, DEPENDANCES, "OSV-Scanner", "osv.json",
                                analyseurs.lire_osv, racine_analyse=self.dossier)
        else:
            self.lanceur.ignorer("osv-scanner", "scan", "base non téléchargée")
            self._echec_outil(DEPENDANCES, "OSV-Scanner", "la base n'a pas pu être téléchargée")

        if self._base_trivy.statut == OK:
            etape = self._etape("trivy", "scan", [
                "trivy", "fs", "--config", f"{CONF}/trivy.yaml", "--ignorefile", "",
                "--scanners", "vuln", "--skip-db-update", "--skip-java-db-update",
                "--offline-scan", "--skip-version-check", "--disable-telemetry",
                "--no-progress", "--include-dev-deps", "--format", "json",
                "--output", "out/trivy.json", "src"], duree_max=600)
            self._lire_resultat(etape, DEPENDANCES, "Trivy", "trivy.json",
                                analyseurs.lire_trivy, racine_analyse=self.dossier)
        else:
            self.lanceur.ignorer("trivy", "scan", "base non téléchargée")
            self._echec_outil(DEPENDANCES, "Trivy", "la base n'a pas pu être téléchargée")

    def _code_php(self, inv):
        # Un composer install par dossier qui a un composer.lock et un
        # composer.json (monorepo : back/, packages/…), 5 au plus.
        # Jamais de script ni de plugin, et pas de fichier autoload généré.
        dossiers_json = {os.path.dirname(c) for c in inv.composer_json}
        a_installer = [v for v in inv.composer_lock
                       if os.path.dirname(v) in dossiers_json][:NB_MAX_AUDITS]
        for n, verrou in enumerate(a_installer, 1):
            dossier = os.path.join("src", os.path.dirname(verrou))
            etape = self._etape(f"composer-install-{n}", "fetch", [
                "composer", "install", "--no-scripts", "--no-plugins", "--no-interaction",
                "--no-progress", "--prefer-dist", "--ignore-platform-reqs",
                "--no-autoloader", "-d", dossier], duree_max=900)
            if etape.statut != OK:
                self.avertissements.append(
                    f"Les dépendances PHP de {os.path.dirname(verrou) or 'la racine'} n'ont pas "
                    "pu être installées : l'analyse de flux (Psalm) est moins précise.")
                if lock_perime(etape.journal):
                    self.problemes.append(probleme_lock_perime(verrou))
        if len([v for v in inv.composer_lock if os.path.dirname(v) in dossiers_json]) > NB_MAX_AUDITS:
            self.avertissements.append(
                f"Plus de {NB_MAX_AUDITS} composer.lock : seules les dépendances des "
                f"{NB_MAX_AUDITS} premiers dossiers ont été installées pour Psalm.")
        if a_installer:
            inv = inventorier(self.src)  # les dossiers vendor viennent d'apparaître

        fichiers.supprimer(os.path.join(self.dossier, "psalm.xml"))
        fichiers.ecrire_nouveau(os.path.join(self.dossier, "psalm.xml"), _psalm_xml(inv))
        etape = self._etape("psalm", "scan", [
            "psalm", "--config=psalm.xml", "--taint-analysis", "--no-cache", "--no-progress",
            # Un seul processus : avec 3, Psalm montait à 5,7 Go sur un gros
            # monorepo Symfony, pour les mêmes résultats.
            "--threads=1", "--report=out/psalm.json"], duree_max=1500, codes_ok=(0, 1, 2),
            memoire_haute=True)
        self._lire_resultat(etape, CODE, "Psalm", "psalm.json", analyseurs.lire_psalm,
                            racine_analyse=self.dossier)
        self._detail = "Psalm — injections SQL, XSS, commandes, chemins"
        return inv

    def _qualite_php(self, inv) -> None:
        """PHPStan : rubrique « Qualité du code », sans effet sur la note."""
        # PHPStan charge <dossier courant>/vendor/autoload.php s'il existe (vu dans
        # son code, bin/phpstan). Le dossier courant est celui de l'analyse, pas le
        # dépôt : il ne doit contenir ni vendor/ ni composer.json.
        for nom in ("vendor", "composer.json"):
            if os.path.lexists(os.path.join(self.dossier, nom)):
                self.lanceur.ignorer("phpstan", "scan", f"{nom} présent dans le dossier de l'analyse")
                self.avertissements.append(
                    "PHPStan n'a pas été lancé : la rubrique « Qualité du code » est absente.")
                return
        try:
            configuration = _phpstan_neon(inv)
        except AnalyseImpossible as e:
            self.lanceur.ignorer("phpstan", "scan", str(e))
            self.avertissements.append(f"PHPStan n'a pas été lancé : {e}")
            return
        fichiers.supprimer(os.path.join(self.dossier, "phpstan.neon"))
        fichiers.ecrire_nouveau(os.path.join(self.dossier, "phpstan.neon"), configuration)
        etape = self._etape("phpstan", "scan", [
            "sh", "-c",
            # proc_open désactivé : PHPStan analyse alors dans un seul processus.
            # Sinon il lance des processus parallèles reliés par une connexion
            # 127.0.0.1, interdite dans le profil scan (« Failed to listen on
            # tcp://127.0.0.1:0 »). Effet de
            # bord voulu : PHPStan ne peut lancer aucun autre programme.
            'exec php -d disable_functions=proc_open /usr/local/bin/phpstan analyse '
            '-c phpstan.neon --error-format=json --no-progress '
            '--memory-limit=3G > out/phpstan.json',
            "sh"], duree_max=900, codes_ok=(0, 1))
        if etape.statut != OK:
            self.avertissements.append(
                f"PHPStan n'a pas donné de résultat ({etape.statut}) : la rubrique "
                "« Qualité du code » est absente. Sans effet sur la note.")
            self._statut_groupe = avancement.ECHEC
            self._detail = "PHPStan sans résultat (sans effet sur la note)"
            return
        try:
            self.qualite = analyseurs.lire_phpstan(
                fichiers.lire_json(os.path.join(self.out, "phpstan.json")),
                racine_analyse=self.dossier, niveau=NIVEAU_PHPSTAN)
        except (fichiers.LectureRefusee, analyseurs.FormatInattendu) as e:
            self.avertissements.append(f"Résultat de PHPStan illisible : {e}. Sans effet sur la note.")
        if self.qualite is None:
            self._statut_groupe = avancement.ECHEC
            self._detail = "PHPStan sans résultat (sans effet sur la note)"
        else:
            self._detail = (f"PHPStan niveau {NIVEAU_PHPSTAN} — "
                            f"{nombre_fr(self.qualite['nb_erreurs'])} erreur(s), sans effet sur la note")

    def _code_regles(self, inv) -> None:
        configs = []
        for langage, present in (("php", inv.php), ("python", inv.python)):
            if present:
                configs += ["--config", f"{REGLES}/{langage}"]
        exclusions = []
        for nom in EXCLUS:
            exclusions += ["--exclude", nom]
        communs = ["--x-ignore-semgrepignore-files", "--disable-nosem", "--no-git-ignore",
                   *exclusions, "--quiet", "--jobs", "3", "--timeout", "30", "src"]

        etape = self._etape("opengrep", "scan", [
            "opengrep", "scan", *configs, "--json-output=out/opengrep.json",
            "--taint-intrafile", *communs], duree_max=1500, codes_ok=(0, 1))
        self._lire_resultat(etape, CODE, "Opengrep", "opengrep.json", analyseurs.lire_semgrep,
                            outil="Opengrep", racine_analyse=self.dossier)
        self._detail = "Opengrep — règles " + " et ".join(
            nom for nom, present in (("PHP", inv.php), ("Python", inv.python)) if present)

    def _code_python(self) -> None:
        exclus = ",".join(f"src/{nom}" for nom in EXCLUS)
        etape = self._etape("bandit", "scan", [
            "bandit", "-r", "src", "--ini", f"{CONF}/bandit.ini", "--ignore-nosec",
            "-f", "json", "-o", "out/bandit.json", "--exit-zero", "-q", "-x", exclus],
            duree_max=900)
        donnees = self._lire_resultat(etape, CODE, "Bandit", "bandit.json",
                                      analyseurs.lire_bandit, racine_analyse=self.dossier)
        if donnees is not None:
            non_lus = analyseurs.erreurs_bandit(donnees, racine_analyse=self.dossier)
            if non_lus:
                self.contexte.fichiers_non_analyses.setdefault(CODE, []).extend(non_lus)
        self._detail = "Bandit"

    # ------------------------------------------------------------- déroulement

    def lancer(self) -> dict:
        if mode_docker():
            pass  # contrôles faits au démarrage du worker (demarrage_docker.preparer)
        elif os.geteuid() != 0:
            raise AnalyseImpossible("asgor-scan doit être lancé en root")
        elif not os.path.ismount(DONNEES):
            # Les données doivent être sur le disque de données, jamais sur le
            # disque système : /var/lib/asgor est un montage de /mnt/data/asgor.
            raise AnalyseImpossible(
                f"{DONNEES} n'est pas monté sur le disque de données : analyse refusée")

        verrou = os.open(VERROU, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(verrou, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(verrou)
            raise AnalyseEnCours("une autre analyse est déjà en cours") from None

        debut = datetime.datetime.now().astimezone()
        depart = time.monotonic()
        try:
            os.makedirs(self.journaux, mode=0o700, exist_ok=True)
            if mode_docker():
                self.lanceur = LanceurDocker(self.id, self.journaux, depart + DUREE_MAX_ANALYSE,
                                             arret=self.arret, dossier_analyses=ANALYSES)
            else:
                self.lanceur = Lanceur(self.id, self.journaux, depart + DUREE_MAX_ANALYSE,
                                       arret=self.arret)
            self.afficher(f"Analyse {self.id} de {self.depot.affichage}")
            if not self.historique_complet:
                self.contexte.historique_non_analyse = True

            self._groupe("clonage", self._clonage)
            inv = self._groupe("langages", self._langages)
            self._groupe("secrets", self._secrets)
            self._groupe("dependances", self._dependances, inv)
            if inv.php:
                inv = self._groupe("flux", self._code_php, inv)
                self._groupe("qualite", self._qualite_php, inv)
            else:
                self.lanceur.ignorer("psalm", "scan", "aucun fichier PHP")
                self.lanceur.ignorer("phpstan", "scan", "aucun fichier PHP")
                self._groupe_ignore("flux", "aucun fichier PHP")
                self._groupe_ignore("qualite", "aucun fichier PHP")
            if inv.php or inv.python:
                self._groupe("regles", self._code_regles, inv)
            else:
                self.lanceur.ignorer("opengrep", "scan", "aucun fichier PHP ou Python")
                self._groupe_ignore("regles", "aucun fichier PHP ou Python")
            if inv.python:
                self._groupe("python", self._code_python)
            else:
                self.lanceur.ignorer("bandit", "scan", "aucun fichier Python")
                self._groupe_ignore("python", "aucun fichier Python")

            rapport = self._groupe("note", self._rapport, inv, debut, depart)
            return rapport
        finally:
            # Dans tous les cas : pas de secret en clair laissé sur le disque.
            fichiers.supprimer(os.path.join(self.out, "gitleaks.json"))
            if not self.garder_sources:
                shutil.rmtree(self.src, ignore_errors=True)
            fcntl.flock(verrou, fcntl.LOCK_UN)
            os.close(verrou)

    def _rapport(self, inv, debut, depart) -> dict:
        self.problemes = supprimer_doublons(self.problemes)
        note = noter(self.problemes, self.contexte)
        fin = datetime.datetime.now().astimezone()
        rapport = {
            "version_format": VERSION_FORMAT,
            "analyse": {
                "id": self.id,
                "debut": debut.isoformat(timespec="seconds"),
                "fin": fin.isoformat(timespec="seconds"),
                "duree_s": round(time.monotonic() - depart, 1),
                "version_moteur": VERSION_MOTEUR,
                "historique_complet": self.historique_complet,
            },
            "depot": {
                "url": f"https://{self.depot.affichage}",
                "proprietaire": self.depot.proprietaire,
                "nom": self.depot.nom,
                "langages": inv.langages,
                "nb_fichiers_php": inv.nb_php,
                "nb_fichiers_python": inv.nb_python,
                # Code d'autres langages, non analysé (bilan de couverture)
                "fichiers_non_pris_en_charge": dict(sorted(inv.non_pris_en_charge.items())),
                **self.infos_depot,
            },
            "note": note,
            "problemes": [p.en_dict() for p in self.problemes],
            # Rubrique « Qualité du code » (PHPStan) : sans effet sur la note.
            "qualite": self.qualite,
            "avertissements": self.avertissements,
            # Seulement les outils qui ont tourné pour ce dépôt ; les autres sont listés
            # à part (ex. pip-audit sans requirements.txt aux versions exactes).
            **self._outils(),
            "etapes": [e.en_dict() for e in self.lanceur.etapes],
        }
        self._ecrire_rapport(rapport)
        self._detail = f"note {note['globale']}"
        return rapport

    def _outils(self) -> dict:
        versions = versions_des_outils()
        lances = outils_lances(self.lanceur.etapes)
        return {
            "outils": {nom: v for nom, v in versions.items() if nom in lances},
            "outils_non_lances": sorted(nom for nom in versions if nom not in lances),
        }

    def _ecrire_rapport(self, rapport: dict) -> None:
        texte = json.dumps(rapport, ensure_ascii=False, indent=2) + "\n"
        os.makedirs(RAPPORTS, mode=0o700, exist_ok=True)
        self.chemin_rapport = os.path.join(RAPPORTS, f"{self.id}.json")
        fichiers.ecrire_nouveau(self.chemin_rapport, texte, 0o600)
        # Le service web (compte asgor-web) lit les rapports : root:asgor-web 0640.
        # Tant que ce groupe n'existe pas (avant l'étape 4 sur la VM), le rapport reste 0600.
        try:
            gid = grp.getgrnam(GROUPE_WEB).gr_gid
        except KeyError:
            gid = None
        # Export SARIF à côté du rapport (même droits).
        self.chemin_sarif = os.path.join(RAPPORTS, f"{self.id}.sarif")
        fichiers.ecrire_nouveau(
            self.chemin_sarif,
            json.dumps(sarif.vers_sarif(rapport), ensure_ascii=False, indent=2) + "\n", 0o600)
        if gid is not None:
            for chemin in (self.chemin_rapport, self.chemin_sarif):
                os.chown(chemin, -1, gid)
                os.chmod(chemin, 0o640)
        # Copie dans le dossier de l'analyse (commande cible de l'étape 3).
        copie = os.path.join(self.out, "rapport.json")
        fichiers.supprimer(copie)
        try:
            fichiers.ecrire_nouveau(copie, texte, 0o600)
        except OSError:
            pass
