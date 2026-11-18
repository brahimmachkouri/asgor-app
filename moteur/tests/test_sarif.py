"""Export SARIF 2.1.0.

La conformité au schéma officiel OASIS a été vérifiée sur des
rapports réels (DVWA, pygoat, un monorepo Symfony) avec la bibliothèque jsonschema.
Ces tests-ci restent sans bibliothèque externe : ils vérifient la structure.
"""

import json
import unittest

from asgor_moteur.sarif import vers_sarif

RAPPORT = {
    "version_format": 2,
    "analyse": {"id": "0" * 32, "debut": "2026-11-15T15:32:10+01:00",
                "fin": "2026-11-15T15:32:35+01:00", "duree_s": 25.0,
                "version_moteur": "0.2", "historique_complet": True},
    "depot": {"url": "https://github.com/exemple/depot", "proprietaire": "exemple",
              "nom": "depot", "commit": "a" * 40, "branche": "main", "nb_commits": 3},
    "note": {"globale": "F", "plafonnements": [{"note_max": "F", "raison": "1 secret détecté"}],
             "domaines": {"secrets": {"score": 50}, "dependances": {"score": 75},
                          "code": {"score": 100}}},
    "problemes": [
        {"id": "1" * 16, "domaine": "secrets", "gravite": "Critique",
         "titre": "Secret détecté : Clé d'API", "fichier": "config/prod é.php", "ligne": 12,
         "outils": ["Gitleaks"], "regle": "generic-api-key", "commit": "b" * 40,
         "secret_masque": "ghp_****", "explication": "Un secret est présent."},
        {"id": "2" * 16, "domaine": "dependances", "gravite": "Élevée",
         "titre": "Faille dans symfony/yaml", "fichier": "composer.lock", "ligne": 0,
         "outils": ["OSV-Scanner", "Trivy"], "regle": "CVE-2026-1", "paquet": "symfony/yaml",
         "version": "v8.1.2", "version_corrigee": "8.1.6", "identifiants": ["CVE-2026-1"]},
        {"id": "3" * 16, "domaine": "dependances", "gravite": "Critique",
         "titre": "Autre faille", "fichier": "composer.lock", "ligne": 0,
         "outils": ["Trivy"], "regle": "CVE-2026-1", "paquet": "symfony/yaml"},
        {"id": "4" * 16, "domaine": "code", "gravite": "Faible", "titre": "Hachage faible",
         "fichier": "", "ligne": 0, "outils": ["Opengrep"], "regle": "php.weak-crypto"},
    ],
    "qualite": {"outil": "PHPStan", "niveau": 5, "nb_erreurs": 280, "nb_fichiers": 92,
                "erreurs": [{"fichier": "a.php", "ligne": 1, "type": "x", "message": "y"}]},
    "avertissements": [],
    "outils": {"Gitleaks": "8.30.1"},
    "etapes": [],
}


class Sarif(unittest.TestCase):
    def setUp(self):
        self.doc = vers_sarif(RAPPORT)
        self.run = self.doc["runs"][0]

    def test_entete(self):
        self.assertEqual(self.doc["version"], "2.1.0")
        self.assertEqual(self.doc["$schema"], "https://json.schemastore.org/sarif-2.1.0.json")
        self.assertEqual(self.run["tool"]["driver"]["name"], "ASGOR")
        self.assertEqual(self.run["tool"]["driver"]["version"], "0.2")
        json.dumps(self.doc)  # sérialisable

    def test_un_resultat_par_probleme(self):
        self.assertEqual(len(self.run["results"]), 4)
        self.assertEqual([r["partialFingerprints"]["asgor/v1"] for r in self.run["results"]],
                         ["1" * 16, "2" * 16, "3" * 16, "4" * 16])

    def test_niveaux(self):
        self.assertEqual([r["level"] for r in self.run["results"]],
                         ["error", "error", "error", "note"])

    def test_regles_et_index(self):
        regles = self.run["tool"]["driver"]["rules"]
        self.assertEqual([r["id"] for r in regles],
                         ["secrets/generic-api-key", "dependances/CVE-2026-1", "code/php.weak-crypto"])
        for resultat in self.run["results"]:
            self.assertEqual(regles[resultat["ruleIndex"]]["id"], resultat["ruleId"])
        # Deux résultats pour la même règle : la gravité la plus haute l'emporte.
        self.assertEqual(regles[1]["properties"]["security-severity"], "9.5")

    def test_emplacements(self):
        secret, dependance, _, sans_fichier = self.run["results"]
        lieu = secret["locations"][0]["physicalLocation"]
        self.assertEqual(lieu["artifactLocation"], {"uri": "config/prod%20%C3%A9.php",
                                                    "uriBaseId": "SRCROOT"})
        self.assertEqual(lieu["region"], {"startLine": 12})
        self.assertNotIn("region", dependance["locations"][0]["physicalLocation"])  # ligne 0
        self.assertNotIn("locations", sans_fichier)
        self.assertEqual(self.run["originalUriBaseIds"]["SRCROOT"]["uri"],
                         "https://github.com/exemple/depot/blob/" + "a" * 40 + "/")
        self.assertEqual(self.run["versionControlProvenance"][0]["revisionId"], "a" * 40)

    def test_secret_masque_seulement(self):
        texte = json.dumps(self.doc, ensure_ascii=False)
        self.assertIn("ghp_****", texte)
        props = self.run["results"][0]["properties"]
        self.assertEqual(props["secret_masque"], "ghp_****")

    def test_version_corrigee_dans_le_message(self):
        self.assertIn("Version corrigée : 8.1.6.", self.run["results"][1]["message"]["text"])

    def test_qualite_resumee_sans_resultats(self):
        self.assertEqual(self.run["properties"]["qualite"]["nb_erreurs"], 280)
        self.assertEqual(self.run["properties"]["qualite"]["effet_sur_la_note"], "aucun")
        self.assertNotIn("a.php", json.dumps(self.doc))  # erreurs PHPStan absentes

    def test_dates_en_utc(self):
        invocation = self.run["invocations"][0]
        self.assertEqual(invocation["startTimeUtc"], "2026-11-15T14:32:10Z")
        self.assertTrue(invocation["executionSuccessful"])

    def test_rapport_vide(self):
        doc = vers_sarif({"analyse": {}, "depot": {}, "note": {}, "problemes": []})
        self.assertEqual(doc["runs"][0]["results"], [])
        self.assertNotIn("versionControlProvenance", doc["runs"][0])
        self.assertEqual(doc["runs"][0]["invocations"], [{"executionSuccessful": True}])


if __name__ == "__main__":
    unittest.main()
