"""Base SQLite d'ASGOR.

Le worker est le seul à écrire. Le service web ouvre la base en lecture seule.
Mode de journal DELETE (pas WAL) : un lecteur n'a besoin d'aucun droit d'écriture.

Les dates sont en heure locale avec le fuseau (« 2026-11-15T15:32:10+01:00 »).
Les comparaisons de dates se font en Python, jamais en comparant des textes.
"""

import datetime
import grp
import os
import pathlib
import sqlite3

from . import avancement

BASE = "/var/lib/asgor/database/asgor.db"
VERSION_SCHEMA = 2   # 2 : résultats écartés comme faux positifs
GROUPE_WEB = "asgor-web"

DELAI_DOUBLON = datetime.timedelta(hours=1)
DELAI_SIGNE_DE_VIE = datetime.timedelta(seconds=60)

EN_ATTENTE = "en_attente"
EN_COURS = "en_cours"
TERMINEE = "terminee"
ECHOUEE = "echouee"
ANNULEE = "annulee"
EXISTANTE = "existante"
ETATS = (EN_ATTENTE, EN_COURS, TERMINEE, ECHOUEE, ANNULEE, EXISTANTE)

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
  id                 TEXT PRIMARY KEY CHECK (length(id) = 32),
  proprietaire       TEXT NOT NULL,
  nom                TEXT NOT NULL,
  etat               TEXT NOT NULL CHECK (etat IN ('en_attente', 'en_cours', 'terminee',
                                                   'echouee', 'annulee', 'existante')),
  historique_complet INTEGER NOT NULL,
  masquee            INTEGER NOT NULL,
  forcee             INTEGER NOT NULL,
  demandee_le        TEXT NOT NULL,
  debut              TEXT,
  fin                TEXT,
  duree_s            REAL,
  commit_sha         TEXT,
  branche            TEXT,
  nb_commits         INTEGER,
  note               TEXT,
  score_secrets      INTEGER,
  score_dependances  INTEGER,
  score_code         INTEGER,
  nb_problemes       INTEGER,
  message            TEXT,
  renvoi_vers        TEXT REFERENCES analyses(id),
  version_moteur     TEXT
);
CREATE INDEX IF NOT EXISTS analyses_depot
  ON analyses (proprietaire COLLATE NOCASE, nom COLLATE NOCASE, fin);
CREATE INDEX IF NOT EXISTS analyses_recent ON analyses (demandee_le);
CREATE TABLE IF NOT EXISTS etapes (
  analyse_id TEXT NOT NULL REFERENCES analyses(id),
  ordre      INTEGER NOT NULL,
  cle        TEXT NOT NULL,
  statut     TEXT NOT NULL,
  detail     TEXT,
  duree_s    REAL,
  PRIMARY KEY (analyse_id, ordre)
);
-- Résultats écartés comme faux positifs (BAREME.md § 6 c), par dépôt :
-- valables pour l'analyse où ils ont été écartés et les suivantes.
CREATE TABLE IF NOT EXISTS ecartes (
  proprietaire TEXT NOT NULL,           -- en minuscules (GitHub ignore la casse)
  nom          TEXT NOT NULL,
  empreinte    TEXT NOT NULL CHECK (length(empreinte) = 16),
  motif        TEXT NOT NULL,
  ip           TEXT,
  le           TEXT NOT NULL,
  analyse_id   TEXT,
  PRIMARY KEY (proprietaire, nom, empreinte)
);
-- Trace de chaque écart et de chaque rétablissement (jamais effacée).
CREATE TABLE IF NOT EXISTS ecartes_journal (
  action       TEXT NOT NULL CHECK (action IN ('ecarter', 'retablir')),
  proprietaire TEXT NOT NULL,
  nom          TEXT NOT NULL,
  empreinte    TEXT NOT NULL,
  motif        TEXT,
  ip           TEXT,
  le           TEXT NOT NULL,
  analyse_id   TEXT
);
CREATE TABLE IF NOT EXISTS worker (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  dernier_signe TEXT NOT NULL,
  version_schema INTEGER NOT NULL
);
"""


def maintenant() -> datetime.datetime:
    return datetime.datetime.now().astimezone()


def _texte(date: datetime.datetime) -> str:
    return date.isoformat(timespec="seconds")


def _date(texte) -> datetime.datetime | None:
    if not isinstance(texte, str):
        return None
    try:
        d = datetime.datetime.fromisoformat(texte)
    except ValueError:
        return None
    return d if d.tzinfo is not None else None


# ===================================================================== worker

def ouvrir_ecriture(chemin: str = BASE) -> sqlite3.Connection:
    """Ouverture par le worker (root). Crée la base si besoin."""
    nouvelle = not os.path.exists(chemin)
    cnx = sqlite3.connect(chemin, timeout=10, isolation_level=None)
    cnx.row_factory = sqlite3.Row
    cnx.execute("PRAGMA journal_mode = DELETE")
    cnx.execute("PRAGMA foreign_keys = ON")
    cnx.executescript(SCHEMA)
    cnx.execute("INSERT OR IGNORE INTO worker (id, dernier_signe, version_schema) "
                "VALUES (1, ?, ?)", (_texte(maintenant()), VERSION_SCHEMA))
    cnx.execute("UPDATE worker SET version_schema = ? WHERE id = 1", (VERSION_SCHEMA,))
    if nouvelle:
        # Le service web (compte asgor-web) lit la base : root:asgor-web 0640.
        try:
            gid = grp.getgrnam(GROUPE_WEB).gr_gid
        except KeyError:
            gid = None
        if gid is not None:
            os.chown(chemin, -1, gid)
            os.chmod(chemin, 0o640)
        else:
            os.chmod(chemin, 0o600)
    return cnx


def creer_analyse(cnx, demande, quand: datetime.datetime | None = None) -> bool:
    """Crée l'analyse « en attente » et ses 9 groupes. Faux si l'id existe déjà."""
    quand = quand or maintenant()
    with cnx:
        cnx.execute("BEGIN")
        curseur = cnx.execute(
            "INSERT OR IGNORE INTO analyses (id, proprietaire, nom, etat, historique_complet, "
            "masquee, forcee, demandee_le) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (demande.id, demande.proprietaire, demande.nom, EN_ATTENTE,
             int(demande.historique_complet), int(demande.masquee), int(demande.forcee),
             _texte(quand)))
        if curseur.rowcount == 0:
            return False
        cnx.executemany(
            "INSERT INTO etapes (analyse_id, ordre, cle, statut) VALUES (?, ?, ?, ?)",
            [(demande.id, i, cle, avancement.EN_ATTENTE)
             for i, cle in enumerate(avancement.CLES, 1)])
    return True


def prochaine_en_attente(cnx) -> sqlite3.Row | None:
    return cnx.execute(
        "SELECT * FROM analyses WHERE etat = ? ORDER BY demandee_le, rowid LIMIT 1",
        (EN_ATTENTE,)).fetchone()


def demarrer(cnx, identifiant: str, version_moteur: str,
             quand: datetime.datetime | None = None) -> None:
    cnx.execute("UPDATE analyses SET etat = ?, debut = ?, version_moteur = ? WHERE id = ?",
                (EN_COURS, _texte(quand or maintenant()), version_moteur, identifiant))


def groupe_commence(cnx, identifiant: str, cle: str) -> None:
    cnx.execute("UPDATE etapes SET statut = ? WHERE analyse_id = ? AND cle = ?",
                (avancement.EN_COURS, identifiant, cle))


def groupe_termine(cnx, identifiant: str, cle: str, statut: str, detail: str,
                   duree_s: float) -> None:
    cnx.execute("UPDATE etapes SET statut = ?, detail = ?, duree_s = ? "
                "WHERE analyse_id = ? AND cle = ?",
                (statut, (detail or "")[:300], round(duree_s, 1), identifiant, cle))


def depot_connu(cnx, identifiant: str, commit: str, branche: str, nb_commits: int) -> None:
    cnx.execute("UPDATE analyses SET commit_sha = ?, branche = ?, nb_commits = ? WHERE id = ?",
                (commit or None, branche or None, nb_commits, identifiant))


def terminer(cnx, identifiant: str, rapport: dict, quand: datetime.datetime | None = None) -> None:
    note = rapport["note"]
    domaines = note["domaines"]
    depot = rapport.get("depot", {})
    cnx.execute(
        "UPDATE analyses SET etat = ?, fin = ?, duree_s = ?, commit_sha = ?, branche = ?, "
        "nb_commits = ?, note = ?, score_secrets = ?, score_dependances = ?, score_code = ?, "
        "nb_problemes = ?, version_moteur = ? WHERE id = ?",
        (TERMINEE, _texte(quand or maintenant()), rapport["analyse"].get("duree_s"),
         depot.get("commit") or None, depot.get("branche") or None, depot.get("nb_commits"),
         note["globale"], domaines["secrets"]["score"], domaines["dependances"]["score"],
         domaines["code"]["score"], nb_problemes_comptes(rapport),
         rapport["analyse"].get("version_moteur"), identifiant))


def mettre_a_jour_note(cnx, identifiant: str, rapport: dict) -> None:
    """Après un écart ou un rétablissement : nouvelle note de l'analyse."""
    note = rapport["note"]
    domaines = note["domaines"]
    cnx.execute(
        "UPDATE analyses SET note = ?, score_secrets = ?, score_dependances = ?, score_code = ?, "
        "nb_problemes = ? WHERE id = ? AND etat = ?",
        (note["globale"], domaines["secrets"]["score"], domaines["dependances"]["score"],
         domaines["code"]["score"], nb_problemes_comptes(rapport), identifiant, TERMINEE))


def nb_problemes_comptes(rapport: dict) -> int:
    return sum(1 for p in rapport.get("problemes", []) if not p.get("ecarte"))


def marquer(cnx, action: str, proprietaire: str, nom: str, empreintes, motif: str, ip: str,
            analyse_id: str, quand: datetime.datetime | None = None) -> None:
    """Écarte ou rétablit des résultats d'un dépôt, avec une trace dans le journal."""
    le = _texte(quand or maintenant())
    proprietaire, nom = proprietaire.lower(), nom.lower()
    with cnx:
        cnx.execute("BEGIN")
        for e in empreintes:
            if action == "ecarter":
                cnx.execute("INSERT OR REPLACE INTO ecartes VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (proprietaire, nom, e, motif, ip or None, le, analyse_id))
            else:
                cnx.execute("DELETE FROM ecartes WHERE proprietaire = ? AND nom = ? AND empreinte = ?",
                            (proprietaire, nom, e))
            cnx.execute("INSERT INTO ecartes_journal VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (action, proprietaire, nom, e, motif or None, ip or None, le, analyse_id))


def _fermer(cnx, identifiant: str, etat: str, message: str | None,
            renvoi: str | None = None, quand: datetime.datetime | None = None) -> None:
    quand = quand or maintenant()
    with cnx:
        cnx.execute("BEGIN")
        ligne = cnx.execute("SELECT debut FROM analyses WHERE id = ?", (identifiant,)).fetchone()
        duree = None
        if ligne is not None and _date(ligne["debut"]) is not None:
            duree = round((quand - _date(ligne["debut"])).total_seconds(), 1)
        cnx.execute("UPDATE analyses SET etat = ?, fin = ?, duree_s = ?, message = ?, "
                    "renvoi_vers = ? WHERE id = ?",
                    (etat, _texte(quand), duree, (message or None) and message[:500],
                     renvoi, identifiant))
        # Les groupes qui n'ont pas fini sont marqués comme la fin de l'analyse.
        statut = avancement.ANNULEE if etat == ANNULEE else avancement.ECHEC
        if etat == EXISTANTE:
            statut = avancement.IGNOREE
        cnx.execute("UPDATE etapes SET statut = ? WHERE analyse_id = ? AND statut IN (?, ?)",
                    (statut, identifiant, avancement.EN_ATTENTE, avancement.EN_COURS))


def echouer(cnx, identifiant: str, message: str, quand=None) -> None:
    _fermer(cnx, identifiant, ECHOUEE, message, quand=quand)


def annuler(cnx, identifiant: str, quand=None) -> None:
    _fermer(cnx, identifiant, ANNULEE, None, quand=quand)


def marquer_existante(cnx, identifiant: str, renvoi_vers: str, quand=None) -> None:
    _fermer(cnx, identifiant, EXISTANTE, None, renvoi=renvoi_vers, quand=quand)


def remettre_en_attente(cnx, identifiant: str) -> None:
    """L'analyse n'a pas pu commencer (asgor-scan tournait à la main) : elle repasse
    en attente, avec ses groupes remis à zéro."""
    with cnx:
        cnx.execute("BEGIN")
        cnx.execute("UPDATE analyses SET etat = ?, debut = NULL, version_moteur = NULL "
                    "WHERE id = ? AND etat = ?", (EN_ATTENTE, identifiant, EN_COURS))
        cnx.execute("UPDATE etapes SET statut = ?, detail = NULL, duree_s = NULL "
                    "WHERE analyse_id = ?", (avancement.EN_ATTENTE, identifiant))


def reprendre_apres_redemarrage(cnx, quand=None) -> list:
    """Au démarrage du worker : les analyses restées « en cours » ont échoué."""
    restees = [r["id"] for r in cnx.execute(
        "SELECT id FROM analyses WHERE etat = ?", (EN_COURS,))]
    for identifiant in restees:
        echouer(cnx, identifiant, "le service d'analyse a redémarré pendant l'analyse", quand)
    return restees


def doublon_recent(cnx, proprietaire: str, nom: str, commit: str, historique_complet: bool,
                   quand: datetime.datetime | None = None) -> str | None:
    """Id d'une analyse terminée du même commit, finie il y a moins d'une heure."""
    quand = quand or maintenant()
    for ligne in cnx.execute(
            "SELECT id, fin FROM analyses WHERE etat = ? AND proprietaire = ? COLLATE NOCASE "
            "AND nom = ? COLLATE NOCASE AND commit_sha = ? AND historique_complet = ? "
            "ORDER BY fin DESC LIMIT 5",
            (TERMINEE, proprietaire, nom, commit, int(historique_complet))):
        fin = _date(ligne["fin"])
        if fin is not None and quand - fin <= DELAI_DOUBLON:
            return ligne["id"]
    return None


def signe_de_vie(cnx, quand=None) -> None:
    cnx.execute("UPDATE worker SET dernier_signe = ? WHERE id = 1",
                (_texte(quand or maintenant()),))


# =============================================================== service web

def ouvrir_lecture(chemin: str = BASE) -> sqlite3.Connection:
    """Ouverture par le service web : lecture seule, attente de 2 s au plus."""
    uri = pathlib.Path(chemin).absolute().as_uri() + "?mode=ro"
    cnx = sqlite3.connect(uri, uri=True, timeout=2)
    cnx.row_factory = sqlite3.Row
    return cnx


def analyse(cnx, identifiant: str) -> sqlite3.Row | None:
    return cnx.execute("SELECT * FROM analyses WHERE id = ?", (identifiant,)).fetchone()


def etapes(cnx, identifiant: str) -> list:
    return cnx.execute("SELECT * FROM etapes WHERE analyse_id = ? ORDER BY ordre",
                       (identifiant,)).fetchall()


def recentes(cnx, nombre: int = 20) -> list:
    """Analyses terminées et non masquées, de la plus récente à la plus ancienne."""
    return cnx.execute("SELECT * FROM analyses WHERE etat = ? AND masquee = 0 "
                       "ORDER BY fin DESC LIMIT ?", (TERMINEE, nombre)).fetchall()


def historique_depot(cnx, proprietaire: str, nom: str, nombre: int = 10) -> list:
    return cnx.execute(
        "SELECT * FROM analyses WHERE etat = ? AND masquee = 0 "
        "AND proprietaire = ? COLLATE NOCASE AND nom = ? COLLATE NOCASE "
        "ORDER BY fin DESC LIMIT ?", (TERMINEE, proprietaire, nom, nombre)).fetchall()


def ecartes_du_depot(cnx, proprietaire: str, nom: str) -> dict:
    """{empreinte: ligne (motif, ip, le)} des résultats écartés pour ce dépôt.
    Base d'avant la version 2 du schéma (table absente) : aucun."""
    try:
        lignes = cnx.execute("SELECT * FROM ecartes WHERE proprietaire = ? AND nom = ?",
                             (proprietaire.lower(), nom.lower())).fetchall()
    except sqlite3.OperationalError:
        return {}
    return {ligne["empreinte"]: ligne for ligne in lignes}


def position_dans_la_file(cnx, identifiant: str) -> int:
    """Nombre d'analyses à passer avant celle-ci (en cours comprise)."""
    ligne = analyse(cnx, identifiant)
    if ligne is None or ligne["etat"] != EN_ATTENTE:
        return 0
    avant = cnx.execute(
        "SELECT count(*) FROM analyses WHERE etat = ? AND "
        "(demandee_le < ? OR (demandee_le = ? AND rowid < (SELECT rowid FROM analyses WHERE id = ?)))",
        (EN_ATTENTE, ligne["demandee_le"], ligne["demandee_le"], identifiant)).fetchone()[0]
    en_cours = cnx.execute("SELECT count(*) FROM analyses WHERE etat = ?",
                           (EN_COURS,)).fetchone()[0]
    return avant + en_cours


def worker_vivant(cnx, quand=None) -> bool:
    ligne = cnx.execute("SELECT dernier_signe FROM worker WHERE id = 1").fetchone()
    if ligne is None:
        return False
    signe = _date(ligne["dernier_signe"])
    if signe is None:
        return False
    return (quand or maintenant()) - signe <= DELAI_SIGNE_DE_VIE
