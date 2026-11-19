"""Tests des corrections faites après le premier scan réel (DVWA).

Les données reprennent la forme et les valeurs des vraies sorties des outils
pour symfony/yaml 8.1.2 dans DVWA.
"""

import functools
import unittest

from asgor_moteur import analyseurs, versions
from asgor_moteur.fusion import supprimer_doublons
from asgor_moteur.modele import CODE, CRITIQUE, ELEVEE, MOYENNE, SECRETS, Probleme
from asgor_moteur.notation import noter

CLE_TEST = b"k" * 32
lire_gitleaks = functools.partial(analyseurs.lire_gitleaks, cle=CLE_TEST)

INSTALLEE = "v8.1.2"


class Versions(unittest.TestCase):
    def test_cle(self):
        self.assertEqual(versions.cle("v8.1.2"), (8, 1, 2))
        self.assertEqual(versions.cle("8.1.0"), versions.cle("8.1"))
        self.assertEqual(versions.cle("2.0.0-beta1"), (2,))
        self.assertIsNone(versions.cle("dev-main"))
        self.assertIsNone(versions.cle(None))

    def test_trivy_plusieurs_branches(self):
        # FixedVersion réel de Trivy pour CVE-2026-109413
        liste = ("7.1.0, 7.2.0, 8.1.0, 8.1.6, 3.0.0, 5.0.0, 6.1.0, 7.4.18, 5.1.0, 5.2.0, "
                 "5.3.0, 5.4.0, 5.4.54, 6.2.0, 6.3.0, 7.4.0, 7.3.0, 4.0.0, 6.4.0, 6.4.45")
        candidates = [v.strip() for v in liste.split(",")]
        self.assertEqual(versions.plus_petite_superieure(INSTALLEE, candidates), "8.1.6")

    def test_osv_plages(self):
        plages = [("2.0.0", "5.4.54"), ("6.0.0", "6.4.45"), ("7.0.0", "7.4.18"), ("8.0.0", "8.1.6")]
        self.assertEqual(versions.depuis_plages(INSTALLEE, plages), "8.1.6")
        self.assertEqual(versions.depuis_plages("6.2.1", plages), "6.4.45")

    def test_composer_contraintes(self):
        contraintes = (">=2.0.0,<3.0.0|>=7.4.0,<7.4.23|>=8.0.0,<8.1.0|>=8.1.0,<8.1.11")
        self.assertEqual(versions.depuis_contraintes_composer(INSTALLEE, contraintes), "8.1.11")
        self.assertEqual(versions.depuis_contraintes_composer("9.0.0", contraintes), "")

    def test_preversion_seulement_sans_version_finale(self):
        self.assertFalse(versions.est_finale("5.2b1"))
        self.assertTrue(versions.est_finale("v8.1.6"))
        # pygoat : pyyaml 5.1
        self.assertEqual(versions.plus_petite_superieure("5.1", ["5.2b1", "5.2"]), "5.2")
        self.assertEqual(versions.plus_petite_superieure("5.1", ["5.2b1"]), "5.2b1")

    def test_version_inconnue(self):
        self.assertEqual(versions.plus_petite_superieure("", ["1.0.0"]), "")
        self.assertEqual(versions.plus_petite_superieure("9.9.9", ["1.0.0"]), "")


class VersionsDansLesAnalyseurs(unittest.TestCase):
    TRIVY = {"SchemaVersion": 2, "Results": [{"Target": "vulnerabilities/api/composer.lock",
                                              "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2026-109413", "PkgName": "symfony/yaml",
        "InstalledVersion": INSTALLEE, "Severity": "HIGH",
        "FixedVersion": "7.1.0, 8.1.0, 8.1.6, 5.4.54, 6.4.45, 7.4.18"}]}]}
    OSV = {"results": [{"source": {"path": "src/vulnerabilities/api/composer.lock"}, "packages": [{
        "package": {"name": "symfony/yaml", "version": INSTALLEE},
        "vulnerabilities": [{"id": "GHSA-2v3c-qxhr-7vpv", "aliases": ["CVE-2026-109413"],
                             "affected": [
            {"package": {"name": "symfony/symfony"},
             "ranges": [{"events": [{"introduced": "2.0.0"}, {"fixed": "5.4.54"}]}]},
            {"package": {"name": "symfony/yaml"},
             "ranges": [{"events": [{"introduced": "2.0.0"}, {"fixed": "5.4.54"}]}]},
            {"package": {"name": "symfony/yaml"},
             "ranges": [{"events": [{"introduced": "8.0.0"}, {"fixed": "8.1.6"}]}]}]}],
        "groups": []}]}]}
    COMPOSER = {"advisories": {"symfony/yaml": [{
        "packageName": "symfony/yaml", "cve": "CVE-2026-109413", "severity": "high",
        "affectedVersions": ">=2.0.0,<3.0.0|>=8.0.0,<8.1.0|>=8.1.0,<8.1.6", "title": "x"}]}}

    def test_les_trois_outils_donnent_8_1_6(self):
        t, = analyseurs.lire_trivy(self.TRIVY)
        o, = analyseurs.lire_osv(self.OSV)
        # Le moteur passe le chemin du verrou à lire_composer_audit (fichier=verrou).
        c, = analyseurs.lire_composer_audit(self.COMPOSER, fichier="vulnerabilities/api/composer.lock",
                                            installees={"symfony/yaml": INSTALLEE})
        self.assertEqual((t.version_corrigee, o.version_corrigee, c.version_corrigee),
                         ("8.1.6", "8.1.6", "8.1.6"))
        fusion, = supprimer_doublons([c, o, t])
        self.assertEqual(fusion.version_corrigee, "8.1.6")

    def test_composer_sans_version_installee(self):
        c, = analyseurs.lire_composer_audit(self.COMPOSER)
        self.assertEqual(c.version_corrigee, "")


class TitresDesSecrets(unittest.TestCase):
    def test_titre_en_francais(self):
        p, = lire_gitleaks([{"RuleID": "generic-api-key", "Secret": "6LelXXXXXXXXXXXX",
                                       "Description": "Detected a Generic API Key, potentially..."}])
        self.assertEqual(p.titre, "Secret détecté : Clé d'API")
        q, = lire_gitleaks([{"RuleID": "regle-rare", "Secret": "x" * 20}])
        self.assertEqual(q.titre, "Secret détecté (règle regle-rare)")


class RaisonDeLaNote(unittest.TestCase):
    def test_raison_affichee_meme_si_deja_f(self):
        problemes = [Probleme(domaine=SECRETS, gravite=CRITIQUE, titre="t", ligne=i)
                     for i in range(2)]
        note = noter(problemes)
        self.assertEqual(note["avant_plafonnement"], "F")  # score Secrets : 0
        self.assertEqual(note["globale"], "F")
        self.assertTrue(any("secret" in p["raison"] for p in note["plafonnements"]))


class FusionATroisLignes(unittest.TestCase):
    def _p(self, outil, ligne, categorie="injection-sql", fichier="sqli/low.php", flux=False):
        return Probleme(domaine=CODE, gravite=ELEVEE, titre="t", fichier=fichier, ligne=ligne,
                        outils=[outil], categorie=categorie, flux=flux)

    def test_cas_reel_dvwa(self):
        # vulnerabilities/sqli/source/low.php : Psalm ligne 11, règles lignes 10 et 31
        problemes = [self._p("Psalm", 11, flux=True), self._p("Opengrep", 10),
                     self._p("Semgrep", 10), self._p("Opengrep", 31), self._p("Semgrep", 31)]
        fusion = supprimer_doublons(problemes)
        self.assertEqual(len(fusion), 2)
        fusionne = [p for p in fusion if "Psalm" in p.outils][0]
        self.assertEqual(fusionne.outils, ["Opengrep", "Psalm", "Semgrep"])
        self.assertEqual(fusionne.ligne, 11)  # la ligne de l'analyse de flux
        self.assertTrue(fusionne.flux)

    def test_meme_outil_jamais_fusionne(self):
        fusion = supprimer_doublons([self._p("Psalm", 22, flux=True), self._p("Psalm", 24, flux=True)])
        self.assertEqual(len(fusion), 2)

    def test_quatre_lignes_d_ecart(self):
        fusion = supprimer_doublons([self._p("Psalm", 10, flux=True), self._p("Opengrep", 14)])
        self.assertEqual(len(fusion), 2)

    def test_categories_ou_fichiers_differents(self):
        self.assertEqual(len(supprimer_doublons(
            [self._p("Psalm", 10), self._p("Opengrep", 11, categorie="xss")])), 2)
        self.assertEqual(len(supprimer_doublons(
            [self._p("Psalm", 10), self._p("Opengrep", 11, fichier="autre.php")])), 2)

    def test_sans_categorie_pas_de_rapprochement(self):
        a = Probleme(domaine=CODE, gravite=MOYENNE, titre="t", fichier="a.php", ligne=10,
                     outils=["Opengrep"], regle="r1")
        b = Probleme(domaine=CODE, gravite=MOYENNE, titre="t", fichier="a.php", ligne=11,
                     outils=["Bandit"], regle="r2")
        self.assertEqual(len(supprimer_doublons([a, b])), 2)

    def test_chaque_faille_fusionnee_une_seule_fois(self):
        # medium.php : Psalm 22, 29, 73 ; règles 21, 28, 71
        problemes = ([self._p("Psalm", n, flux=True) for n in (22, 29, 73)]
                     + [self._p("Opengrep", n) for n in (21, 28, 71)])
        fusion = supprimer_doublons(problemes)
        self.assertEqual(sorted(p.ligne for p in fusion), [22, 29, 73])
        self.assertTrue(all(p.outils == ["Opengrep", "Psalm"] for p in fusion))


if __name__ == "__main__":
    unittest.main()
