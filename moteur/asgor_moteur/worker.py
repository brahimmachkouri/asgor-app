"""Worker ASGOR.

Tourne en root, sans aucun port ouvert. Relève la file des demandes déposées
par le service web, lance les analyses une par une, écrit l'avancement et le
résultat dans la base. C'est le seul programme qui écrit dans la base.

Un seul fil d'exécution : pendant une analyse, le moteur demande toutes les
demi-secondes s'il doit s'arrêter (fonction arret). Le worker en profite pour
relever la file et donner son signe de vie.
"""

import os
import shutil
import signal
import sys
import time
import traceback

from . import base, ecartes, file, fichiers
from . import moteur as module_moteur
from .avancement import Observateur
from .url import UrlInvalide, valider_url

INTERVALLE_RELEVE = 2.0       # secondes entre deux relevés de la file
INTERVALLE_SIGNE = 10.0       # secondes entre deux signes de vie
PAUSE_SI_OCCUPE = 30.0        # asgor-scan lancé à la main : on réessaie plus tard


class ObservateurBase(Observateur):
    """Recopie l'avancement de l'analyse dans la base."""

    def __init__(self, cnx, identifiant: str):
        self.cnx = cnx
        self.id = identifiant

    def groupe_commence(self, cle):
        base.groupe_commence(self.cnx, self.id, cle)

    def groupe_termine(self, cle, statut, detail, duree_s):
        base.groupe_termine(self.cnx, self.id, cle, statut, detail, duree_s)

    def depot_connu(self, commit, branche, nb_commits):
        base.depot_connu(self.cnx, self.id, commit, branche, nb_commits)


class Worker:
    def __init__(self, chemin_base: str = base.BASE, dossier_file: str = file.FILE,
                 dossier_analyses: str | None = None, fabrique_analyse=None,
                 dossier_rapports: str | None = None,
                 journal=None, horloge=time.monotonic):
        self.cnx = base.ouvrir_ecriture(chemin_base)
        self.dossier_file = dossier_file
        self.dossier_analyses = dossier_analyses or module_moteur.ANALYSES
        self.dossier_rapports = dossier_rapports or module_moteur.RAPPORTS
        self.fabrique_analyse = fabrique_analyse or module_moteur.Analyse
        self.journal = journal or (lambda message: print(message, file=sys.stderr, flush=True))
        self.horloge = horloge
        self.en_cours = None              # id de l'analyse en cours
        self.annuler_en_cours = False
        self.arret_du_service = False
        self.renvoi = None                # doublon trouvé pour l'analyse en cours
        self._dernier_releve = float("-inf")
        self._dernier_signe = float("-inf")
        self.pause_jusqu_a = float("-inf")

    # ------------------------------------------------------------ démarrage
    def reprendre(self) -> None:
        """Au démarrage : les analyses restées « en cours » ont échoué."""
        for identifiant in base.reprendre_apres_redemarrage(self.cnx):
            self.journal(f"analyse {identifiant} interrompue par un redémarrage : marquée en échec")
            self._nettoyer(identifiant)

    # ------------------------------------------------------------- entretien
    def entretien(self, force: bool = False) -> None:
        """Signe de vie et relevé de la file (au plus toutes les 2 s)."""
        maintenant = self.horloge()
        if force or maintenant - self._dernier_signe >= INTERVALLE_SIGNE:
            base.signe_de_vie(self.cnx)
            self._dernier_signe = maintenant
        if not force and maintenant - self._dernier_releve < INTERVALLE_RELEVE:
            return
        self._dernier_releve = maintenant
        marquages = []
        demandes, annulations, rejets = file.relever(self.dossier_file, marquages=marquages)
        for rejet in rejets:
            self.journal(rejet)
        for marquage in marquages:
            try:
                self._marquer(marquage)
            except Exception:  # noqa: BLE001 — une erreur imprévue ne doit pas arrêter le worker
                self.journal(f"marquage {marquage.id} : erreur interne\n{traceback.format_exc()}")
        for demande in demandes:
            if base.creer_analyse(self.cnx, demande):
                self.journal(f"demande {demande.id} : {demande.proprietaire}/{demande.nom}")
        for identifiant in annulations:
            self._annuler(identifiant)

    def _lire_rapport(self, identifiant: str) -> dict | None:
        if not module_moteur.identifiant_valide(identifiant):
            return None
        try:
            rapport = fichiers.lire_json(os.path.join(self.dossier_rapports, f"{identifiant}.json"))
        except (OSError, ValueError, fichiers.LectureRefusee):
            return None
        return rapport if isinstance(rapport, dict) else None

    def _marquer(self, m: file.Marquage) -> None:
        """Écart ou rétablissement de résultats (BAREME.md § 6 c)."""
        ligne = base.analyse(self.cnx, m.analyse)
        if ligne is None or ligne["etat"] != base.TERMINEE:
            self.journal(f"marquage {m.id} refusé : analyse {m.analyse} absente ou non terminée")
            return
        rapport = self._lire_rapport(m.analyse)
        if rapport is None:
            self.journal(f"marquage {m.id} refusé : rapport {m.analyse} illisible")
            return
        connues = {p.get("id") for p in rapport.get("problemes", [])}
        retenues = [e for e in m.empreintes if e in connues]
        if len(retenues) != len(m.empreintes):
            self.journal(f"marquage {m.id} : {len(m.empreintes) - len(retenues)} "
                         "identifiant(s) absent(s) du rapport ignoré(s)")
        if not retenues:
            return
        base.marquer(self.cnx, m.action, ligne["proprietaire"], ligne["nom"], retenues,
                     m.motif, m.ip, m.analyse)
        self._appliquer_ecartes(m.analyse, ligne, rapport)
        self.journal(f"marquage {m.id} : {len(retenues)} résultat(s) "
                     f"{'écarté(s)' if m.action == file.ECARTER else 'rétabli(s)'} "
                     f"pour {ligne['proprietaire']}/{ligne['nom']}, nouvelle note {rapport['note']['globale']}")

    def _appliquer_ecartes(self, identifiant: str, ligne, rapport: dict) -> None:
        """Recalcule la note sans les résultats écartés et réécrit le rapport."""
        liste = base.ecartes_du_depot(self.cnx, ligne["proprietaire"], ligne["nom"])
        if ecartes.appliquer(rapport, liste):
            ecartes.reecrire(self.dossier_rapports, identifiant, rapport)
            base.mettre_a_jour_note(self.cnx, identifiant, rapport)

    def _annuler(self, identifiant: str) -> None:
        ligne = base.analyse(self.cnx, identifiant)
        if ligne is None:
            return
        if ligne["etat"] == base.EN_ATTENTE:
            base.annuler(self.cnx, identifiant)
            self.journal(f"analyse {identifiant} annulée avant de commencer")
        elif ligne["etat"] == base.EN_COURS and identifiant == self.en_cours:
            self.annuler_en_cours = True
            self.journal(f"analyse {identifiant} : annulation demandée")

    def _arret(self) -> bool:
        """Appelée par le moteur toutes les demi-secondes pendant une étape."""
        self.entretien()
        return self.annuler_en_cours or self.arret_du_service

    # ------------------------------------------------------------ analyse
    def _doublon(self, ligne):
        def doublon(commit: str) -> bool:
            if ligne["forcee"]:
                return False
            self.renvoi = base.doublon_recent(self.cnx, ligne["proprietaire"], ligne["nom"],
                                              commit, bool(ligne["historique_complet"]))
            return self.renvoi is not None
        return doublon

    def _nettoyer(self, identifiant: str) -> None:
        """Après chaque analyse : le dossier de l'analyse est supprimé en entier."""
        if not module_moteur.identifiant_valide(identifiant):
            return
        fichiers.supprimer_arbre(os.path.join(self.dossier_analyses, identifiant))

    def executer(self, ligne) -> None:
        identifiant = ligne["id"]
        self.en_cours, self.annuler_en_cours, self.renvoi = identifiant, False, None
        try:
            try:
                # La base est écrite par ce worker, mais on revalide quand même.
                depot = valider_url(f"https://github.com/{ligne['proprietaire']}/{ligne['nom']}")
            except UrlInvalide:
                base.echouer(self.cnx, identifiant, "adresse du dépôt invalide")
                return
            base.demarrer(self.cnx, identifiant, module_moteur.VERSION_MOTEUR)
            self.journal(f"analyse {identifiant} : début ({depot.affichage})")
            analyse = self.fabrique_analyse(
                depot, id_analyse=identifiant,
                historique_complet=bool(ligne["historique_complet"]),
                observateur=ObservateurBase(self.cnx, identifiant),
                arret=self._arret, doublon=self._doublon(ligne),
                afficher=lambda *_: None)
            try:
                rapport = analyse.lancer()
            except module_moteur.AnalyseExistante:
                base.marquer_existante(self.cnx, identifiant, self.renvoi)
                self.journal(f"analyse {identifiant} : commit déjà analysé ({self.renvoi})")
            except module_moteur.AnalyseAnnulee:
                if self.arret_du_service and not self.annuler_en_cours:
                    base.echouer(self.cnx, identifiant,
                                 "le service d'analyse a été arrêté pendant l'analyse")
                else:
                    base.annuler(self.cnx, identifiant)
                self.journal(f"analyse {identifiant} : annulée")
            except module_moteur.AnalyseEnCours:
                # asgor-scan tourne à la main : on remet la demande en attente.
                base.remettre_en_attente(self.cnx, identifiant)
                self.pause_jusqu_a = self.horloge() + PAUSE_SI_OCCUPE
                self.journal(f"analyse {identifiant} : une autre analyse tourne, réessai plus tard")
            except module_moteur.AnalyseImpossible as e:
                base.echouer(self.cnx, identifiant, str(e))
                self.journal(f"analyse {identifiant} : impossible : {e}")
            except Exception:  # noqa: BLE001 — une erreur imprévue ne doit pas arrêter le worker
                self.journal(f"analyse {identifiant} : erreur interne\n{traceback.format_exc()}")
                base.echouer(self.cnx, identifiant, "erreur interne du service d'analyse")
            else:
                # Résultats déjà écartés pour ce dépôt : ils ne comptent pas non plus ici.
                deja = base.ecartes_du_depot(self.cnx, ligne["proprietaire"], ligne["nom"])
                if deja and ecartes.appliquer(rapport, deja):
                    ecartes.reecrire(self.dossier_rapports, identifiant, rapport)
                base.terminer(self.cnx, identifiant, rapport)
                self.journal(f"analyse {identifiant} : terminée, note {rapport['note']['globale']}")
        finally:
            self._nettoyer(identifiant)
            self.en_cours, self.annuler_en_cours = None, False

    # --------------------------------------------------------------- boucle
    def un_tour(self) -> bool:
        """Un passage : entretien, puis au plus une analyse. Vrai si une analyse a tourné."""
        self.entretien(force=True)
        if self.arret_du_service or self.horloge() < self.pause_jusqu_a:
            return False
        ligne = base.prochaine_en_attente(self.cnx)
        if ligne is None:
            return False
        self.executer(ligne)
        return True

    def boucle(self) -> None:
        self.reprendre()
        while not self.arret_du_service:
            if not self.un_tour():
                time.sleep(INTERVALLE_RELEVE)


def main() -> int:
    if module_moteur.mode_docker():
        # Image Docker : compte 10001, données dans des volumes, outils par le filtre.
        try:
            from . import demarrage_docker
            demarrage_docker.preparer(module_moteur.CLE_EMPREINTES)
        except demarrage_docker.DemarrageImpossible as e:
            print(f"asgor-worker : {e}", file=sys.stderr)
            return 2
    else:
        if os.geteuid() != 0:
            print("asgor-worker doit être lancé en root", file=sys.stderr)
            return 2
        if not os.path.ismount(module_moteur.DONNEES):
            print(f"{module_moteur.DONNEES} n'est pas monté sur le disque de données : arrêt",
                  file=sys.stderr)
            return 2
    worker = Worker()

    def arreter(_signal, _cadre):
        worker.arret_du_service = True
    signal.signal(signal.SIGTERM, arreter)
    signal.signal(signal.SIGINT, arreter)
    worker.journal("asgor-worker : démarrage")
    worker.boucle()
    worker.journal("asgor-worker : arrêt")
    return 0
