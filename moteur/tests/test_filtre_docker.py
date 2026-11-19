"""Filtre du socket Docker : demandes refusées, configuration écrite par le filtre seul."""

import json
import unittest

from asgor_moteur import filtre_docker as f

ANALYSE = "0123456789abcdef0123456789abcdef"
IMAGE = "sha256:" + "a" * 64
CONTENEUR = "b" * 64


def lancer(**autres):
    demande = {"action": "lancer", "profil": "scan", "analyse": ANALYSE,
               "commande": ["gitleaks", "version"], "memoire_haute": False}
    demande.update(autres)
    return demande


class TestDemandes(unittest.TestCase):
    def test_demandes_valides(self):
        for demande in (lancer(), lancer(profil="fetch", memoire_haute=True),
                        {"action": "version"}, {"action": "tuer", "conteneur": CONTENEUR}):
            with self.subTest(demande=demande):
                self.assertIs(f.verifier_demande(demande), demande)

    def test_demandes_refusees(self):
        cas = [
            [],                                                     # pas un objet
            {"action": "exec", "conteneur": CONTENEUR},             # action inconnue
            {"action": "build"},
            {},
            lancer(profil="hote"),                                  # profil inconnu
            lancer(profil="nettoyage"),
            lancer(analyse="../../etc"),                            # identifiant invalide
            lancer(analyse=ANALYSE.upper()),
            lancer(analyse=ANALYSE + "0"),
            lancer(memoire_haute="oui"),
            lancer(memoire_haute=1),
            lancer(commande="gitleaks version"),                    # pas une liste
            lancer(commande=[]),
            lancer(commande=["gitleaks", 3]),
            lancer(commande=[""]),
            lancer(commande=["sh", "a\x00b"]),
            lancer(commande=["x"] * 513),
            lancer(commande=["a" * 8193]),
            dict(lancer(), image="alpine"),                         # champ inconnu
            dict(lancer(), HostConfig={"Privileged": True}),
            dict(lancer(), montages=["/:/hote"]),
            {"action": "lancer", "profil": "scan", "analyse": ANALYSE, "commande": ["a"]},  # manquant
            {"action": "tuer", "conteneur": "abc"},                 # conteneur invalide
            {"action": "tuer", "conteneur": CONTENEUR, "signal": "HUP"},
        ]
        for demande in cas:
            with self.subTest(demande=str(demande)[:80]):
                with self.assertRaises(f.Refus):
                    f.verifier_demande(demande)


class TestConfiguration(unittest.TestCase):
    def setUp(self):
        self.reglages = f.Reglages({})
        self.reglages.processeurs = 3.0

    def test_scan(self):
        c = f.configuration(lancer(), IMAGE, self.reglages)
        h = c["HostConfig"]
        self.assertEqual(c["Image"], IMAGE)
        self.assertEqual(c["User"], "10001:10001")
        self.assertEqual(c["WorkingDir"], f"/var/lib/asgor/jobs/{ANALYSE}")
        self.assertEqual(c["Cmd"][-2:], ["gitleaks", "version"])
        self.assertEqual(c["Cmd"][:3], ["/bin/sh", "-c", 'umask 077 && exec "$@"'])
        self.assertTrue(c["NetworkDisabled"])
        self.assertEqual(h["NetworkMode"], "none")
        self.assertTrue(h["ReadonlyRootfs"])
        self.assertFalse(h["Privileged"])
        self.assertEqual(h["CapDrop"], ["ALL"])
        self.assertEqual(h["CapAdd"], [])
        self.assertEqual(h["SecurityOpt"], ["no-new-privileges:true"])
        self.assertEqual(h["Memory"], 4 * 1024**3)
        self.assertEqual(h["MemorySwap"], h["Memory"])
        self.assertEqual(h["PidsLimit"], 512)
        self.assertEqual(h["NanoCpus"], 3_000_000_000)
        for vide in ("Binds", "VolumesFrom", "Devices", "DeviceRequests", "CapAdd", "ExtraHosts"):
            self.assertEqual(h[vide], [])
        self.assertNotIn("PidMode", h)
        self.assertNotIn("UsernsMode", h)
        self.assertEqual(h["IpcMode"], "private")
        self.assertFalse(any(v.startswith(("HTTPS_PROXY", "https_proxy")) for v in c["Env"]))
        self.assertIn("COMPOSER_DISABLE_NETWORK=1", c["Env"])

    def test_montages_seulement_ceux_prevus(self):
        for profil in ("scan", "fetch"):
            with self.subTest(profil=profil):
                montages = f.configuration(lancer(profil=profil), IMAGE, self.reglages)["HostConfig"]["Mounts"]
                self.assertEqual([m["Type"] for m in montages], ["volume"] * 3)
                analyses, cache, regles = montages
                self.assertEqual(analyses["Source"], "asgor-analyses")
                self.assertEqual(analyses["VolumeOptions"]["Subpath"], ANALYSE)
                self.assertEqual(analyses["Target"], f"/var/lib/asgor/jobs/{ANALYSE}")
                self.assertFalse(analyses["ReadOnly"])
                self.assertEqual(cache["Source"], "asgor-cache")
                self.assertEqual(cache["ReadOnly"], profil == "scan")
                self.assertEqual(regles["Source"], "asgor-regles")
                self.assertTrue(regles["ReadOnly"])
                texte = json.dumps(montages)
                for interdit in ("docker.sock", "asgor-donnees", "asgor-secrets", "asgor-controle",
                                 "asgor-file", '"bind"'):
                    self.assertNotIn(interdit, texte)

    def test_fetch(self):
        c = f.configuration(lancer(profil="fetch"), IMAGE, self.reglages)
        self.assertFalse(c["NetworkDisabled"])
        self.assertEqual(c["HostConfig"]["NetworkMode"], "asgor-fetch")
        self.assertIn("HTTPS_PROXY=http://proxy:3128", c["Env"])
        self.assertIn("GIT_ALLOW_PROTOCOL=https", c["Env"])

    def test_memoire_haute(self):
        c = f.configuration(lancer(memoire_haute=True), IMAGE, self.reglages)
        self.assertEqual(c["HostConfig"]["Memory"], 6 * 1024**3)
        self.assertEqual(c["HostConfig"]["MemorySwap"], 6 * 1024**3)

    def test_commande_jamais_interpretee_par_le_shell(self):
        c = f.configuration(lancer(commande=["echo", "$(id); rm -rf /"]), IMAGE, self.reglages)
        # La commande est passée en arguments de « exec "$@" », jamais dans le texte de -c.
        self.assertEqual(c["Cmd"][2], 'umask 077 && exec "$@"')
        self.assertEqual(c["Cmd"][-1], "$(id); rm -rf /")


class FauxDocker:
    def __init__(self):
        self.appels = []
        self.etiquettes = {CONTENEUR: {f.ETIQUETTE: "scan"}}

    def json(self, methode, chemin, corps=None, attendus=(200,), **options):
        self.appels.append((methode, chemin))
        if chemin == "/containers/create":
            return {"Id": CONTENEUR}
        if chemin.endswith("/json") and chemin.startswith("/containers/"):
            ident = chemin.split("/")[2]
            return {"Config": {"Labels": self.etiquettes.get(ident, {})},
                    "State": {"Status": "exited", "ExitCode": 0, "OOMKilled": False}}
        return None


class TestFiltre(unittest.TestCase):
    def test_conteneur_inconnu_refuse(self):
        filtre = f.Filtre(FauxDocker(), f.Reglages({}), IMAGE)
        for action in ("attendre", "tuer", "journaux", "supprimer"):
            with self.subTest(action=action):
                with self.assertRaises(f.Refus):
                    filtre.traiter({"action": action, "conteneur": "c" * 64})

    def test_cycle_d_une_etape(self):
        docker = FauxDocker()
        filtre = f.Filtre(docker, f.Reglages({}), IMAGE)
        reponse, _ = filtre.traiter(lancer())
        self.assertEqual(reponse, {"ok": True, "conteneur": CONTENEUR})
        reponse, _ = filtre.traiter({"action": "attendre", "conteneur": CONTENEUR})
        self.assertEqual(reponse["code"], 0)
        filtre.traiter({"action": "supprimer", "conteneur": CONTENEUR})
        with self.assertRaises(f.Refus):
            filtre.traiter({"action": "tuer", "conteneur": CONTENEUR})

    def test_conteneur_sans_etiquette_refuse(self):
        docker = FauxDocker()
        filtre = f.Filtre(docker, f.Reglages({}), IMAGE)
        filtre.traiter(lancer())
        docker.etiquettes[CONTENEUR] = {}
        with self.assertRaises(f.Refus):
            filtre.traiter({"action": "tuer", "conteneur": CONTENEUR})


class TestJournal(unittest.TestCase):
    def test_trames(self):
        flux = b"\x01\x00\x00\x00\x00\x00\x00\x03abc" + b"\x02\x00\x00\x00\x00\x00\x00\x02de"
        self.assertEqual(f.separer_journal(flux), b"abcde")


if __name__ == "__main__":
    unittest.main()
