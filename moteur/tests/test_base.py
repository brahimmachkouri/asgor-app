"""Base SQLite (lot 3 de l'étape 4) : écritures du worker, lectures du service web."""

import datetime
import os
import sqlite3
import tempfile
import unittest

from asgor_moteur import avancement, base
from asgor_moteur.file import Demande

PARIS = datetime.timezone(datetime.timedelta(hours=1))
T0 = datetime.datetime(2026, 11, 15, 15, 0, 0, tzinfo=PARIS)


def demande(n: int, proprietaire="Organisation", nom="monDepot", historique=True, masquee=False):
    return Demande(id=f"{n:032x}", url=f"https://github.com/{proprietaire}/{nom}",
                   proprietaire=proprietaire, nom=nom, historique_complet=historique,
                   masquee=masquee, forcee=False)


RAPPORT = {
    "analyse": {"duree_s": 25.0, "version_moteur": "0.2"},
    "depot": {"commit": "a" * 40, "branche": "main", "nb_commits": 845},
    "note": {"globale": "F", "domaines": {"secrets": {"score": 0},
                                          "dependances": {"score": 67},
                                          "code": {"score": 0}}},
    "problemes": [{}, {}, {}],
}


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.chemin = os.path.join(tmp.name, "asgor.db")
        self.cnx = base.ouvrir_ecriture(self.chemin)
        self.addCleanup(self.cnx.close)

    def _lecture(self):
        cnx = base.ouvrir_lecture(self.chemin)
        self.addCleanup(cnx.close)
        return cnx

    def _terminee(self, n, fin, commit="a" * 40, **options):
        d = demande(n, **options)
        base.creer_analyse(self.cnx, d, T0)
        base.demarrer(self.cnx, d.id, "0.2", T0)
        rapport = {**RAPPORT, "depot": {**RAPPORT["depot"], "commit": commit}}
        base.terminer(self.cnx, d.id, rapport, fin)
        return d.id

    def test_creation(self):
        self.assertTrue(base.creer_analyse(self.cnx, demande(1), T0))
        self.assertFalse(base.creer_analyse(self.cnx, demande(1), T0))  # même id : ignoré
        lecture = self._lecture()
        a = base.analyse(lecture, demande(1).id)
        self.assertEqual((a["etat"], a["proprietaire"], a["historique_complet"]),
                         (base.EN_ATTENTE, "Organisation", 1))
        etapes = base.etapes(lecture, demande(1).id)
        self.assertEqual([e["cle"] for e in etapes], list(avancement.CLES))
        self.assertTrue(all(e["statut"] == avancement.EN_ATTENTE for e in etapes))

    def test_deroulement(self):
        d = demande(1)
        base.creer_analyse(self.cnx, d, T0)
        self.assertEqual(base.prochaine_en_attente(self.cnx)["id"], d.id)
        base.demarrer(self.cnx, d.id, "0.2", T0)
        self.assertIsNone(base.prochaine_en_attente(self.cnx))
        base.groupe_commence(self.cnx, d.id, "clonage")
        base.depot_connu(self.cnx, d.id, "a" * 40, "main", 845)
        base.groupe_termine(self.cnx, d.id, "clonage", avancement.TERMINEE, "845 commits, 5 Mo", 2.04)
        base.terminer(self.cnx, d.id, RAPPORT, T0 + datetime.timedelta(seconds=25))
        lecture = self._lecture()
        a = base.analyse(lecture, d.id)
        self.assertEqual((a["etat"], a["note"], a["score_dependances"], a["nb_problemes"]),
                         (base.TERMINEE, "F", 67, 3))
        e = base.etapes(lecture, d.id)[0]
        self.assertEqual((e["statut"], e["detail"], e["duree_s"]),
                         (avancement.TERMINEE, "845 commits, 5 Mo", 2.0))

    def test_lecture_seule(self):
        base.creer_analyse(self.cnx, demande(1), T0)
        lecture = self._lecture()
        with self.assertRaises(sqlite3.OperationalError):
            lecture.execute("UPDATE analyses SET note = 'A'")
        with self.assertRaises(sqlite3.OperationalError):
            lecture.execute("DELETE FROM analyses")

    def test_journal_delete(self):
        mode = self.cnx.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode, "delete")

    def test_echec_annulation_existante(self):
        for n in (1, 2, 3):
            base.creer_analyse(self.cnx, demande(n), T0)
        base.demarrer(self.cnx, demande(1).id, "0.2", T0)
        base.groupe_commence(self.cnx, demande(1).id, "clonage")
        base.echouer(self.cnx, demande(1).id, "dépôt trop gros", T0 + datetime.timedelta(seconds=5))
        base.annuler(self.cnx, demande(2).id, T0)
        base.marquer_existante(self.cnx, demande(3).id, demande(1).id, T0)
        lecture = self._lecture()
        a1, a2, a3 = (base.analyse(lecture, demande(n).id) for n in (1, 2, 3))
        self.assertEqual((a1["etat"], a1["message"], a1["duree_s"]),
                         (base.ECHOUEE, "dépôt trop gros", 5.0))
        self.assertEqual(a2["etat"], base.ANNULEE)
        self.assertEqual((a3["etat"], a3["renvoi_vers"]), (base.EXISTANTE, demande(1).id))
        statuts = {e["statut"] for e in base.etapes(lecture, demande(1).id)}
        self.assertEqual(statuts, {avancement.ECHEC})
        statuts = {e["statut"] for e in base.etapes(lecture, demande(2).id)}
        self.assertEqual(statuts, {avancement.ANNULEE})

    def test_redemarrage(self):
        base.creer_analyse(self.cnx, demande(1), T0)
        base.creer_analyse(self.cnx, demande(2), T0)
        base.demarrer(self.cnx, demande(1).id, "0.2", T0)
        self.assertEqual(base.reprendre_apres_redemarrage(self.cnx), [demande(1).id])
        a = base.analyse(self.cnx, demande(1).id)
        self.assertEqual(a["etat"], base.ECHOUEE)
        self.assertIn("redémarré", a["message"])
        self.assertEqual(base.analyse(self.cnx, demande(2).id)["etat"], base.EN_ATTENTE)

    def test_doublon_recent(self):
        fin = T0 + datetime.timedelta(minutes=5)
        ident = self._terminee(1, fin)
        trouve = base.doublon_recent
        self.assertEqual(trouve(self.cnx, "Organisation", "monDepot", "a" * 40, True,
                                fin + datetime.timedelta(minutes=59)), ident)
        # Casse différente : même dépôt pour GitHub.
        self.assertEqual(trouve(self.cnx, "organisation", "MONDEPOT", "a" * 40, True,
                                fin + datetime.timedelta(minutes=10)), ident)
        # Plus d'une heure, autre commit, autre option d'historique : pas de doublon.
        self.assertIsNone(trouve(self.cnx, "Organisation", "monDepot", "a" * 40, True,
                                 fin + datetime.timedelta(minutes=61)))
        self.assertIsNone(trouve(self.cnx, "Organisation", "monDepot", "b" * 40, True, fin))
        self.assertIsNone(trouve(self.cnx, "Organisation", "monDepot", "a" * 40, False, fin))
        # Fuseau différent (heure d'été / d'hiver) : comparaison en vraies dates.
        utc = (fin + datetime.timedelta(minutes=30)).astimezone(datetime.timezone.utc)
        self.assertEqual(trouve(self.cnx, "Organisation", "monDepot", "a" * 40, True, utc), ident)

    def test_recentes_et_historique(self):
        visibles = [self._terminee(n, T0 + datetime.timedelta(minutes=n)) for n in (1, 2, 3)]
        self._terminee(4, T0 + datetime.timedelta(minutes=10), masquee=True)
        self._terminee(5, T0 + datetime.timedelta(minutes=11), nom="autre")
        base.creer_analyse(self.cnx, demande(6), T0)  # en attente : pas dans les récentes
        lecture = self._lecture()
        recentes = [r["id"] for r in base.recentes(lecture)]
        self.assertEqual(recentes, [demande(5, nom="autre").id] + visibles[::-1])
        historique = [r["id"] for r in base.historique_depot(lecture, "organisation", "mondepot")]
        self.assertEqual(historique, visibles[::-1])

    def test_position_dans_la_file(self):
        for n in (1, 2, 3):
            base.creer_analyse(self.cnx, demande(n), T0 + datetime.timedelta(seconds=n))
        base.demarrer(self.cnx, demande(1).id, "0.2", T0)
        lecture = self._lecture()
        self.assertEqual(base.position_dans_la_file(lecture, demande(2).id), 1)
        self.assertEqual(base.position_dans_la_file(lecture, demande(3).id), 2)
        self.assertEqual(base.position_dans_la_file(lecture, demande(1).id), 0)

    def test_worker_vivant(self):
        base.signe_de_vie(self.cnx, T0)
        lecture = self._lecture()
        self.assertTrue(base.worker_vivant(lecture, T0 + datetime.timedelta(seconds=59)))
        self.assertFalse(base.worker_vivant(lecture, T0 + datetime.timedelta(seconds=61)))

    def test_etat_invalide_refuse_par_la_base(self):
        base.creer_analyse(self.cnx, demande(1), T0)
        with self.assertRaises(sqlite3.IntegrityError):
            self.cnx.execute("UPDATE analyses SET etat = 'piraté' WHERE id = ?", (demande(1).id,))

    def test_droits_du_fichier(self):
        # Sur la VM (root, groupe asgor-web présent) : root:asgor-web 0640.
        # Sur le Mac (pas de groupe asgor-web) : 0600.
        import grp
        try:
            gid = grp.getgrnam(base.GROUPE_WEB).gr_gid
        except KeyError:
            gid = None
        infos = os.stat(self.chemin)
        if gid is None:
            self.assertEqual(infos.st_mode & 0o777, 0o600)
        else:
            self.assertEqual((infos.st_mode & 0o777, infos.st_gid), (0o640, gid))


if __name__ == "__main__":
    unittest.main()
