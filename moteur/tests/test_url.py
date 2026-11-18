import unittest

from asgor_moteur.url import Depot, UrlInvalide, valider_url


class UrlsAcceptees(unittest.TestCase):
    def test_forme_simple(self):
        self.assertEqual(
            valider_url("https://github.com/Organisation/monDepot"),
            Depot("Organisation", "monDepot"),
        )

    def test_suffixe_git_et_barre_finale(self):
        self.assertEqual(valider_url("https://github.com/a/b.git"), Depot("a", "b"))
        self.assertEqual(valider_url("https://github.com/a/b/"), Depot("a", "b"))

    def test_caracteres_autorises(self):
        self.assertEqual(
            valider_url("https://github.com/mon-org/depot_1.v2-test"),
            Depot("mon-org", "depot_1.v2-test"),
        )

    def test_url_de_clonage_reconstruite(self):
        depot = valider_url("https://github.com/digininja/DVWA")
        self.assertEqual(depot.url_clonage, "https://github.com/digininja/DVWA.git")
        self.assertEqual(depot.url_api, "https://api.github.com/repos/digininja/DVWA")


class UrlsRefusees(unittest.TestCase):
    REFUSEES = [
        # autre protocole
        "http://github.com/a/b",
        "git://github.com/a/b",
        "ssh://git@github.com/a/b",
        "git@github.com:a/b.git",
        "file:///etc/passwd",
        "HTTPS://github.com/a/b",
        # autre hôte
        "https://gitlab.com/a/b",
        "https://github.com.exemple.fr/a/b",
        "https://exemple.fr/github.com/a/b",
        "https://www.github.com/a/b",
        "https://GitHub.com/a/b",
        "https://github.com./a/b",
        "https://127.0.0.1/a/b",
        # identifiants, port
        "https://jeton@github.com/a/b",
        "https://user:motdepasse@github.com/a/b",
        "https://github.com@exemple.fr/a/b",
        "https://github.com:443/a/b",
        # chemin trop court ou trop long
        "https://github.com/",
        "https://github.com/a",
        "https://github.com/a/",
        "https://github.com/a/b/c",
        "https://github.com/a/b/tree/main",
        "https://github.com//b",
        # paramètres, fragment
        "https://github.com/a/b?x=1",
        "https://github.com/a/b#x",
        # caractères inattendus
        "https://github.com/a/b c",
        " https://github.com/a/b",
        "https://github.com/a/b ",
        "https://github.com/a/b\n",
        "https://github.com/a/b\x00",
        "https://github.com/a/b%2e%2e",
        "https://github.com/a/b;id",
        "https://github.com/a/$(id)",
        "https://github.com/a/b\\c",
        "https://github.com/é/b",
        "https://github.com/a/dépôt",
        # options de git cachées dans un nom
        "https://github.com/-a/b",
        "https://github.com/a-/b",
        "https://github.com/a--b/c",
        "https://github.com/--upload-pack=x/b",
        # noms réservés
        "https://github.com/a/.",
        "https://github.com/a/..",
        "https://github.com/a/.git",
        "https://github.com/../b",
        # longueurs
        "https://github.com/" + "a" * 40 + "/b",
        "https://github.com/a/" + "b" * 101,
        "",
    ]

    def test_refus(self):
        for url in self.REFUSEES:
            with self.subTest(url=url):
                with self.assertRaises(UrlInvalide):
                    valider_url(url)

    def test_types_refuses(self):
        for valeur in (None, 12, b"https://github.com/a/b", ["https://github.com/a/b"]):
            with self.subTest(valeur=valeur):
                with self.assertRaises(UrlInvalide):
                    valider_url(valeur)


if __name__ == "__main__":
    unittest.main()
