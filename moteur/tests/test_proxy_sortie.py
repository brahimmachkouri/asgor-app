"""Proxy de sortie des étapes « fetch » : chaque refus, et le relais d'un tunnel."""

import os
import socket
import tempfile
import threading
import unittest

from asgor_moteur import proxy_sortie as p

CONF = os.path.join(os.path.dirname(__file__), "..", "conf", "proxy-domaines.txt")


def faux_resolveur(table):
    def resoudre(nom, port, type=None):
        if nom not in table:
            raise socket.gaierror("introuvable")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (a, port, 0, 0) if ":" in a else (a, port)) for a in table[nom]]
    return resoudre


class TestAnalyse(unittest.TestCase):
    def test_connect_443_accepte(self):
        self.assertEqual(p.analyser_demande(b"CONNECT GitHub.com:443 HTTP/1.1\r\nHost: x"), "github.com")

    def test_refus(self):
        cas = {
            b"GET http://github.com/ HTTP/1.1": 405,
            b"CONNECT github.com:80 HTTP/1.1": 403,
            b"CONNECT github.com:4430 HTTP/1.1": 403,
            b"CONNECT github.com HTTP/1.1": 403,
            b"CONNECT 140.82.121.4:443 HTTP/1.1": 403,
            b"CONNECT [2606:4700::1111]:443 HTTP/1.1": 403,
            b"CONNECT 0x7f000001:443 HTTP/1.1": 403,
            b"CONNECT 2130706433:443 HTTP/1.1": 403,
            b"CONNECT github.com.:443 HTTP/1.1": 403,
            b"CONNECT git_hub.com:443 HTTP/1.1": 403,
            b"CONNECT github.com:443": 400,
            b"CONNECT g\xc3\xa9.com:443 HTTP/1.1": 400,
        }
        for demande, code in cas.items():
            with self.subTest(demande=demande):
                with self.assertRaises(p.Refus) as e:
                    p.analyser_demande(demande)
                self.assertEqual(e.exception.code, code)


class TestAdresses(unittest.TestCase):
    def test_publiques_et_non_publiques(self):
        self.assertTrue(p.est_publique("140.82.121.4"))
        self.assertTrue(p.est_publique("2606:4700:4700::1111"))
        for adresse in ("127.0.0.1", "10.57.0.9", "172.17.0.1", "192.168.65.254", "169.254.169.254",
                        "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1",
                        "::ffff:127.0.0.1", "224.0.0.1", "198.18.0.1"):
            with self.subTest(adresse=adresse):
                self.assertFalse(p.est_publique(adresse))

    def test_une_seule_adresse_privee_suffit_a_refuser(self):
        resolveur = faux_resolveur({"github.com": ["140.82.121.4", "10.0.0.5"]})
        with self.assertRaises(p.Refus):
            p.resoudre("github.com", resolveur)

    def test_nom_introuvable(self):
        with self.assertRaises(p.Refus) as e:
            p.resoudre("absent.example", faux_resolveur({}))
        self.assertEqual(e.exception.code, 502)

    def test_adresses_publiques_gardees(self):
        resolveur = faux_resolveur({"github.com": ["140.82.121.4", "140.82.121.4"]})
        self.assertEqual(p.resoudre("github.com", resolveur), [(socket.AF_INET, ("140.82.121.4", 443))])


class TestListe(unittest.TestCase):
    def test_liste_du_depot_valide(self):
        liste = p.lire_liste(CONF)
        self.assertIn("github.com", liste)
        self.assertIn("pypi.org", liste)

    def test_nom_invalide_refuse(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("github.com\n*.github.com\n")
        try:
            with self.assertRaises(ValueError):
                p.lire_liste(f.name)
        finally:
            os.unlink(f.name)


class TestServeur(unittest.TestCase):
    """De bout en bout : vrai serveur local, faux résolveur."""

    def setUp(self):
        table = {"github.com": ["127.0.0.1"], "pypi.org": ["10.1.2.3"]}
        self.serveur = p.Serveur(("127.0.0.1", 0), frozenset({"github.com", "pypi.org"}),
                                 faux_resolveur(table))
        threading.Thread(target=self.serveur.serve_forever, daemon=True).start()
        self.port = self.serveur.server_address[1]

    def tearDown(self):
        self.serveur.shutdown()
        self.serveur.server_close()

    def demander(self, requete: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(requete)
            recu = b""
            while True:
                morceau = s.recv(4096)
                if not morceau:
                    return recu
                recu += morceau

    def test_refus_de_bout_en_bout(self):
        cas = {
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n": b"403",          # hors liste
            b"CONNECT github.com:443 HTTP/1.1\r\n\r\n": b"403",           # mène à 127.0.0.1
            b"CONNECT pypi.org:443 HTTP/1.1\r\n\r\n": b"403",             # mène au réseau local
            b"CONNECT 1.1.1.1:443 HTTP/1.1\r\n\r\n": b"403",              # adresse IP
            b"GET http://github.com/ HTTP/1.1\r\n\r\n": b"405",
            b"CONNECT github.com:443 HTTP/1.1\r\n\r\nGET /": b"400",      # données en trop
        }
        for requete, code in cas.items():
            with self.subTest(requete=requete):
                reponse = self.demander(requete)
                self.assertTrue(reponse.startswith(b"HTTP/1.1 " + code), reponse)
                self.assertNotIn(b"200 Connection established", reponse)

    def test_requete_trop_longue(self):
        reponse = self.demander(b"CONNECT github.com:443 HTTP/1.1\r\nX: " + b"a" * 9000 + b"\r\n\r\n")
        self.assertTrue(reponse.startswith(b"HTTP/1.1 431"), reponse)


class TestRelais(unittest.TestCase):
    def test_relais_dans_les_deux_sens_puis_fin(self):
        client_a, proxy_a = socket.socketpair()
        proxy_b, distant_b = socket.socketpair()
        fil = threading.Thread(target=p.relayer, args=(proxy_a, proxy_b), daemon=True)
        fil.start()
        client_a.sendall(b"bonjour")
        self.assertEqual(distant_b.recv(100), b"bonjour")
        distant_b.sendall(b"reponse")
        self.assertEqual(client_a.recv(100), b"reponse")
        client_a.shutdown(socket.SHUT_WR)
        self.assertEqual(distant_b.recv(100), b"")
        distant_b.close()
        fil.join(5)
        self.assertFalse(fil.is_alive())
        for s in (client_a, proxy_a, proxy_b):
            s.close()


if __name__ == "__main__":
    unittest.main()
