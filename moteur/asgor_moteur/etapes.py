"""Lancement d'une étape d'analyse dans l'isolation (asgor-sandbox)."""

import os
import re
import subprocess
import time
from dataclasses import dataclass

SANDBOX = "/usr/local/sbin/asgor-sandbox"

OK = "ok"
ECHEC = "échec"
DELAI = "délai dépassé"
IGNOREE = "ignorée"
ANNULEE = "annulée"

INTERVALLE_SURVEILLANCE = 0.5  # secondes entre deux vérifications de l'annulation

_UNITES = {"B": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
_MEMOIRE = re.compile(r"Memory peak:\s*([0-9]+(?:\.[0-9]+)?)\s*([BKMGT])")


@dataclass
class Etape:
    nom: str
    profil: str
    statut: str
    code_retour: int | None = None
    duree_s: float = 0.0
    memoire_max_octets: int | None = None
    detail: str = ""
    journal: str = ""  # chemin du journal de l'étape (pas dans le rapport)

    def en_dict(self) -> dict:
        return {
            "nom": self.nom,
            "profil": self.profil,
            "statut": self.statut,
            "code_retour": self.code_retour,
            "duree_s": round(self.duree_s, 1),
            "memoire_max_octets": self.memoire_max_octets,
            "detail": self.detail,
        }


def _fin_du_journal(chemin: str, taille: int = 4000) -> str:
    try:
        with open(chemin, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - taille))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def memoire_max(journal: str) -> int | None:
    """Lit « Memory peak: 12.5M » dans le bilan affiché par systemd-run."""
    trouves = _MEMOIRE.findall(journal)
    if not trouves:
        return None
    valeur, unite = trouves[-1]
    return int(float(valeur) * _UNITES[unite])


class Lanceur:
    """Lance les étapes d'une analyse et tient compte de la durée totale."""

    def __init__(self, id_analyse: str, dossier_journaux: str, echeance: float,
                 sandbox: str = SANDBOX, arret=None):
        self.id = id_analyse
        self.dossier_journaux = dossier_journaux
        self.echeance = echeance  # time.monotonic() à ne pas dépasser
        self.sandbox = sandbox
        # arret() -> bool : vrai quand l'utilisateur a demandé l'annulation.
        self.arret = arret or (lambda: False)
        self.annulee = False
        self.etapes = []

    def _arreter(self, processus, unite: str) -> None:
        """Arrête l'unité systemd de l'étape (et donc tous ses processus)."""
        try:
            subprocess.run(["systemctl", "stop", unite], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass  # systemctl absent (tests sur le Mac) ou bloqué : on tue au moins le lanceur
        processus.kill()
        processus.wait()

    def ignorer(self, nom: str, profil: str, raison: str) -> Etape:
        etape = Etape(nom=nom, profil=profil, statut=IGNOREE, detail=raison)
        self.etapes.append(etape)
        return etape

    def lancer(self, nom: str, profil: str, commande: list, duree_max: int = 1800,
               codes_ok: tuple = (0,), memoire_haute: bool = False) -> Etape:
        if self.annulee or self.arret():
            self.annulee = True
            etape = Etape(nom=nom, profil=profil, statut=ANNULEE, detail="analyse annulée")
            self.etapes.append(etape)
            return etape
        restant = self.echeance - time.monotonic()
        if restant <= 1:
            etape = Etape(nom=nom, profil=profil, statut=DELAI,
                          detail="durée totale de l'analyse dépassée")
            self.etapes.append(etape)
            return etape
        delai = min(duree_max, restant)

        journal = os.path.join(self.dossier_journaux, f"{len(self.etapes) + 1:02d}-{nom}.log")
        environnement = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "ASGOR_SANDBOX_STATS": "1",
            # Limite de mémoire « haute » de /etc/asgor/sandbox.conf (Psalm).
            "ASGOR_SANDBOX_MEMOIRE": "haute" if memoire_haute else "normale",
        }
        debut = time.monotonic()
        with open(journal, "wb") as sortie:
            processus = subprocess.Popen(
                [self.sandbox, profil, self.id, "--", *commande],
                stdin=subprocess.DEVNULL, stdout=sortie, stderr=subprocess.STDOUT,
                env=environnement, close_fds=True)
            # asgor-sandbox remplace son processus par systemd-run (exec) :
            # l'unité porte donc le numéro de ce processus.
            unite = f"asgor-{profil}-{self.id}-{processus.pid}.service"
            limite = time.monotonic() + delai
            code = None
            statut = None
            # Attente par petits pas, pour réagir à une annulation en moins d'une seconde.
            while statut is None:
                try:
                    code = processus.wait(timeout=INTERVALLE_SURVEILLANCE)
                    statut = OK if code in codes_ok else ECHEC
                except subprocess.TimeoutExpired:
                    if self.arret():
                        self._arreter(processus, unite)
                        self.annulee = True
                        code, statut = None, ANNULEE
                    elif time.monotonic() >= limite:
                        self._arreter(processus, unite)
                        code, statut = None, DELAI
        duree = time.monotonic() - debut

        fin = _fin_du_journal(journal)
        etape = Etape(nom=nom, profil=profil, statut=statut, code_retour=code,
                      duree_s=duree, memoire_max_octets=memoire_max(fin), journal=journal)
        if statut == ECHEC:
            etape.detail = f"code de retour {code} ; journal : {journal}"
        elif statut == DELAI:
            etape.detail = f"arrêtée après {int(delai)} s"
        elif statut == ANNULEE:
            etape.detail = "analyse annulée"
        self.etapes.append(etape)
        return etape
