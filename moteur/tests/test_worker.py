"""Worker (lot 4 de l'étape 4), avec un faux moteur à la place de l'analyse réelle."""

import os
import tempfile
import unittest

from asgor_moteur import avancement, base, file
from asgor_moteur import moteur as module_moteur
from asgor_moteur.worker import Worker

RAPPORT = {
    "analyse": {"duree_s": 12.0, "version_moteur": "0.2"},
    "depot": {"commit": "c" * 40, "branche": "main", "nb_commits": 10},
    "note": {"globale": "B", "domaines": {"secrets": {"score": 100},
                                          "dependances": {"score": 80},
                                          "code": {"score": 92}}},
    "problemes": [{}],
}


class FauxMoteur:
    """Remplace moteur.Analyse. Le comportement est choisi d'après le nom du dépôt."""
    lancees = []

    def __init__(self, depot, id_analyse, historique_complet, observateur, arret, doublon,
                 afficher):
        self.depot, self.id = depot, id_analyse
        self.historique_complet = historique_complet
        self.observateur, self.arret, self.doublon = observateur, arret, doublon
        self.dossier = None

    def lancer(self):
        FauxMoteur.lancees.append((self.depot.nom, self.id, self.historique_complet))
        dossier = os.path.join(FauxMoteur.analyses, self.id, "src")
        os.makedirs(dossier)
        open(os.path.join(dossier, "fichier"), "w").close()
        obs = self.observateur
        obs.groupe_commence("clonage")
        if self.doublon("c" * 40):
            raise module_moteur.AnalyseExistante("c" * 40)
        obs.depot_connu("c" * 40, "main", 10)
        obs.groupe_termine("clonage", avancement.TERMINEE, "10 commits, 1 Mo", 1.0)
        comportement = self.depot.nom
        if comportement == "impossible":
            raise module_moteur.AnalyseImpossible("dépôt trop gros : 900 Mo (limite : 500 Mo)")
        if comportement == "plante":
            raise RuntimeError("bogue imprévu")
        if comportement == "occupe":
            raise module_moteur.AnalyseEnCours("une autre analyse est déjà en cours")
        if comportement == "long":
            obs.groupe_commence("secrets")
            for _ in range(200):          # comme le lanceur : arret() à chaque demi-seconde
                if self.arret():
                    obs.groupe_termine("secrets", avancement.ANNULEE, "", 0.5)
                    raise module_moteur.AnalyseAnnulee()
                if FauxMoteur.pendant_l_attente:
                    FauxMoteur.pendant_l_attente()
            raise AssertionError("l'annulation n'a pas été vue")
        return RAPPORT


class Horloge:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        self.t += 1.0   # chaque appel avance d'une seconde : le relevé se fait tous les 2 appels
        return self.t


class TestWorker(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.file = os.path.join(tmp.name, "file")
        self.analyses = os.path.join(tmp.name, "jobs")
        os.makedirs(self.file)
        os.makedirs(self.analyses)
        FauxMoteur.lancees = []
        FauxMoteur.analyses = self.analyses
        FauxMoteur.pendant_l_attente = None
        self.journal = []
        self.worker = Worker(chemin_base=os.path.join(tmp.name, "asgor.db"),
                             dossier_file=self.file, dossier_analyses=self.analyses,
                             fabrique_analyse=FauxMoteur, journal=self.journal.append,
                             horloge=Horloge())
        self.addCleanup(self.worker.cnx.close)

    def _deposer(self, nom, **options):
        return file.deposer_demande(f"https://github.com/exemple/{nom}", dossier=self.file,
                                    **options)

    def _etat(self, identifiant):
        return base.analyse(self.worker.cnx, identifiant)

    def test_analyse_terminee(self):
        ident = self._deposer("normal", historique_complet=False)
        self.assertTrue(self.worker.un_tour())
        a = self._etat(ident)
        self.assertEqual((a["etat"], a["note"], a["commit_sha"], a["nb_problemes"]),
                         (base.TERMINEE, "B", "c" * 40, 1))
        self.assertEqual(FauxMoteur.lancees, [("normal", ident, False)])
        self.assertEqual(os.listdir(self.analyses), [])     # dossier de l'analyse supprimé
        self.assertEqual(os.listdir(self.file), [])         # demande relevée
        e = base.etapes(self.worker.cnx, ident)[0]
        self.assertEqual((e["cle"], e["statut"], e["detail"]),
                         ("clonage", avancement.TERMINEE, "10 commits, 1 Mo"))

    def test_une_analyse_a_la_fois_dans_l_ordre(self):
        premiere = self._deposer("normal")
        os.utime(os.path.join(self.file, f"{premiere}.json"), (1000, 1000))
        seconde = self._deposer("autre-depot")  # autre dépôt : pas de doublon
        self.assertTrue(self.worker.un_tour())
        self.assertEqual(self._etat(premiere)["etat"], base.TERMINEE)
        self.assertEqual(self._etat(seconde)["etat"], base.EN_ATTENTE)
        self.assertTrue(self.worker.un_tour())
        self.assertEqual(self._etat(seconde)["etat"], base.TERMINEE)
        self.assertFalse(self.worker.un_tour())               # plus rien à faire

    def test_doublon_de_moins_d_une_heure(self):
        premiere = self._deposer("normal")
        self.worker.un_tour()
        seconde = self._deposer("normal")
        self.worker.un_tour()
        a = self._etat(seconde)
        self.assertEqual((a["etat"], a["renvoi_vers"]), (base.EXISTANTE, premiere))
        # « Analyser quand même » : forcee
        troisieme = self._deposer("normal", forcee=True)
        self.worker.un_tour()
        self.assertEqual(self._etat(troisieme)["etat"], base.TERMINEE)

    def test_doublon_autre_option_d_historique(self):
        self._deposer("normal")
        self.worker.un_tour()
        seconde = self._deposer("normal", historique_complet=False)
        self.worker.un_tour()
        self.assertEqual(self._etat(seconde)["etat"], base.TERMINEE)

    def test_analyse_impossible(self):
        ident = self._deposer("impossible")
        self.worker.un_tour()
        a = self._etat(ident)
        self.assertEqual((a["etat"], a["message"]),
                         (base.ECHOUEE, "dépôt trop gros : 900 Mo (limite : 500 Mo)"))
        statuts = [e["statut"] for e in base.etapes(self.worker.cnx, ident)]
        self.assertEqual(statuts[0], avancement.TERMINEE)
        self.assertTrue(all(s == avancement.ECHEC for s in statuts[1:]))
        self.assertEqual(os.listdir(self.analyses), [])

    def test_erreur_imprevue(self):
        ident = self._deposer("plante")
        self.worker.un_tour()
        a = self._etat(ident)
        self.assertEqual((a["etat"], a["message"]),
                         (base.ECHOUEE, "erreur interne du service d'analyse"))
        self.assertNotIn("bogue", a["message"])                # le détail reste dans le journal
        self.assertTrue(any("bogue imprévu" in ligne for ligne in self.journal))
        # Le worker continue : l'analyse suivante tourne.
        suivante = self._deposer("normal")
        self.worker.un_tour()
        self.assertEqual(self._etat(suivante)["etat"], base.TERMINEE)

    def test_annulation_en_attente(self):
        ident = self._deposer("normal")
        file.deposer_annulation(ident, self.file)
        self.assertFalse(self.worker.un_tour())
        self.assertEqual(self._etat(ident)["etat"], base.ANNULEE)
        self.assertEqual(FauxMoteur.lancees, [])

    def test_annulation_pendant_l_analyse(self):
        ident = self._deposer("long")
        compteur = {"n": 0}

        def annuler_au_troisieme_passage():
            compteur["n"] += 1
            if compteur["n"] == 3:
                file.deposer_annulation(ident, self.file)
        FauxMoteur.pendant_l_attente = annuler_au_troisieme_passage
        self.worker.un_tour()
        a = self._etat(ident)
        self.assertEqual(a["etat"], base.ANNULEE)
        statuts = {e["cle"]: e["statut"] for e in base.etapes(self.worker.cnx, ident)}
        self.assertEqual(statuts["secrets"], avancement.ANNULEE)
        self.assertEqual(statuts["note"], avancement.ANNULEE)
        self.assertEqual(os.listdir(self.analyses), [])

    def test_nouvelle_demande_relevee_pendant_l_analyse(self):
        ident = self._deposer("long")
        autre = {}

        def deposer_puis_annuler():
            if "id" not in autre:
                autre["id"] = self._deposer("normal")
            elif base.analyse(self.worker.cnx, autre["id"]) is not None:
                file.deposer_annulation(ident, self.file)
        FauxMoteur.pendant_l_attente = deposer_puis_annuler
        self.worker.un_tour()
        # La demande déposée pendant l'analyse longue est déjà dans la base.
        self.assertEqual(self._etat(autre["id"])["etat"], base.EN_ATTENTE)
        self.assertEqual(self._etat(ident)["etat"], base.ANNULEE)

    def test_arret_du_service_pendant_l_analyse(self):
        ident = self._deposer("long")

        def arreter():
            self.worker.arret_du_service = True
        FauxMoteur.pendant_l_attente = arreter
        self.worker.un_tour()
        a = self._etat(ident)
        self.assertEqual(a["etat"], base.ECHOUEE)
        self.assertIn("arrêté", a["message"])
        self.assertFalse(self.worker.un_tour())                # plus aucune analyse lancée

    def test_autre_analyse_deja_en_cours(self):
        ident = self._deposer("occupe")
        self.worker.un_tour()
        a = self._etat(ident)
        self.assertEqual((a["etat"], a["debut"]), (base.EN_ATTENTE, None))
        self.assertFalse(self.worker.un_tour())                # pause de 30 s

    def test_redemarrage(self):
        ident = self._deposer("normal")
        self.worker.entretien(force=True)
        base.demarrer(self.worker.cnx, ident, "0.2")
        os.makedirs(os.path.join(self.analyses, ident, "src"))
        self.worker.reprendre()
        a = self._etat(ident)
        self.assertEqual(a["etat"], base.ECHOUEE)
        self.assertIn("redémarré", a["message"])
        self.assertEqual(os.listdir(self.analyses), [])

    def test_fichier_piege_journalise(self):
        with open(os.path.join(self.file, "pas-une-demande.txt"), "w") as f:
            f.write("x")
        self.assertFalse(self.worker.un_tour())
        self.assertTrue(any("nom de fichier inattendu" in ligne for ligne in self.journal))
        self.assertEqual(os.listdir(self.file), [])

    def test_signe_de_vie(self):
        self.worker.un_tour()
        self.assertTrue(base.worker_vivant(self.worker.cnx))


if __name__ == "__main__":
    unittest.main()


class WorkerAvecLeVraiMoteur(unittest.TestCase):
    """Worker + vrai moteur.Analyse ; seul le lanceur d'outils est simulé."""

    def test_rapport_reel_dans_la_base(self):
        from unittest import mock
        from tests.test_deroulement import _faux_lanceur
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        racine = tmp.name
        cle = os.path.join(racine, "empreintes.key")
        with open(cle, "wb") as f:
            f.write(b"k" * 32)
        analyses = os.path.join(racine, "jobs")
        dossier_file = os.path.join(racine, "file")
        os.makedirs(analyses)
        os.makedirs(dossier_file)
        for correctif in (
                mock.patch.object(module_moteur, "ANALYSES", analyses),
                mock.patch.object(module_moteur, "RAPPORTS", os.path.join(racine, "reports")),
                mock.patch.object(module_moteur, "JOURNAUX", os.path.join(racine, "logs")),
                mock.patch.object(module_moteur, "VERROU", os.path.join(racine, "verrou")),
                mock.patch.object(module_moteur, "CLE_EMPREINTES", cle),
                mock.patch.object(module_moteur, "Lanceur", _faux_lanceur(analyses)),
                mock.patch.object(module_moteur.os, "geteuid", lambda: 0),
                mock.patch.object(module_moteur.os.path, "ismount", lambda chemin: True)):
            correctif.start()
            self.addCleanup(correctif.stop)
        worker = Worker(chemin_base=os.path.join(racine, "asgor.db"), dossier_file=dossier_file,
                        dossier_analyses=analyses, journal=lambda m: None, horloge=Horloge())
        self.addCleanup(worker.cnx.close)
        ident = file.deposer_demande("https://github.com/exemple/depot", dossier=dossier_file)
        self.assertTrue(worker.un_tour())

        a = base.analyse(worker.cnx, ident)
        self.assertEqual((a["etat"], a["note"], a["commit_sha"], a["branche"], a["nb_commits"]),
                         (base.TERMINEE, "F", "a" * 40, "main", 412))
        self.assertIsNotNone(a["score_secrets"])
        etapes = base.etapes(worker.cnx, ident)
        self.assertEqual([e["cle"] for e in etapes], list(avancement.CLES))
        self.assertTrue(all(e["statut"] == avancement.TERMINEE for e in etapes),
                        [(e["cle"], e["statut"]) for e in etapes])
        self.assertTrue(os.path.exists(os.path.join(racine, "reports", f"{ident}.json")))
        self.assertTrue(os.path.exists(os.path.join(racine, "reports", f"{ident}.sarif")))
        self.assertEqual(os.listdir(analyses), [])
        # Même commit juste après : renvoi vers ce rapport, sans relancer d'outil.
        seconde = file.deposer_demande("https://github.com/exemple/depot", dossier=dossier_file)
        worker.un_tour()
        self.assertEqual(base.analyse(worker.cnx, seconde)["etat"], base.EXISTANTE)
