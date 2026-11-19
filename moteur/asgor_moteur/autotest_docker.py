"""Autotest d'isolation de l'image Docker (équivalent d'asgor-sandbox-selftest).

Lancé dans le conteneur du worker : python3 -m asgor_moteur.autotest_docker
Crée deux analyses d'essai, lance des étapes « scan » et « fetch » par le filtre, et
vérifie ce que chaque étape peut et ne peut pas faire. Envoie aussi au filtre des
demandes interdites, qui doivent être refusées. Code de retour 1 si un contrôle échoue.
"""

import os
import secrets
import shutil
import sys
import time

from .etapes import FiltreInjoignable, demander_filtre

ANALYSES = os.environ.get("ASGOR_ANALYSES", "/var/lib/asgor/jobs")


class Autotest:
    def __init__(self):
        self.a = secrets.token_hex(16)
        self.b = secrets.token_hex(16)
        self.echecs = 0
        self.total = 0

    # -------------------------------------------------------------- outils
    def note(self, libelle: str, reussi: bool, detail: str = "") -> None:
        self.total += 1
        if not reussi:
            self.echecs += 1
        print(f"{'OK   ' if reussi else 'ÉCHEC'}  {libelle}{'  — ' + detail if detail and not reussi else ''}",
              flush=True)

    def etape(self, profil: str, commande: list, analyse: str = None, memoire_haute=False,
              delai: float = 300) -> tuple:
        """Lance une étape et attend sa fin : (code de retour, journal)."""
        reponse, _ = demander_filtre({"action": "lancer", "profil": profil, "analyse": analyse or self.a,
                                      "commande": commande, "memoire_haute": memoire_haute})
        conteneur = reponse["conteneur"]
        try:
            limite = time.monotonic() + delai
            while True:
                etat, _ = demander_filtre({"action": "attendre", "conteneur": conteneur})
                if etat["termine"]:
                    break
                if time.monotonic() > limite:
                    demander_filtre({"action": "tuer", "conteneur": conteneur})
                    return None, "délai dépassé"
                time.sleep(0.3)
            _, texte = demander_filtre({"action": "journaux", "conteneur": conteneur})
            return etat["code"], texte.decode("utf-8", "replace")
        finally:
            demander_filtre({"action": "supprimer", "conteneur": conteneur})

    def controle(self, libelle: str, profil: str, script: str, **options) -> None:
        """Contrôle réussi si le script shell finit avec le code 0."""
        try:
            code, texte = self.etape(profil, ["sh", "-c", script], **options)
            self.note(libelle, code == 0, f"code {code} : {texte.strip()[-300:]}")
        except FiltreInjoignable as e:
            self.note(libelle, False, str(e))

    def refus(self, libelle: str, demande: dict) -> None:
        """Contrôle réussi si le filtre refuse la demande."""
        try:
            demander_filtre(demande)
            self.note(libelle, False, "demande acceptée")
        except FiltreInjoignable as e:
            self.note(libelle, True, str(e))

    # ------------------------------------------------------------ contrôles
    def lancer(self) -> int:
        for analyse in (self.a, self.b):
            for sous in ("", "src", "out", "home"):
                os.makedirs(os.path.join(ANALYSES, analyse, sous), mode=0o700, exist_ok=True)
        with open(os.path.join(ANALYSES, self.b, "out", "temoin"), "w") as f:
            f.write("autre analyse\n")
        try:
            self.controles_worker()
            self.controles_scan()
            self.controles_fetch()
            self.controles_filtre()
        finally:
            for analyse in (self.a, self.b):
                shutil.rmtree(os.path.join(ANALYSES, analyse), ignore_errors=True)
        print(f"\n{self.total - self.echecs} contrôles sur {self.total} OK.")
        if self.echecs:
            print(f"Isolation : {self.echecs} contrôle(s) en échec.")
            return 1
        print("Isolation : tous les contrôles sont OK.")
        return 0

    def controles_worker(self) -> None:
        print("== Worker")
        self.note("le worker ne voit pas le socket Docker", not os.path.exists("/var/run/docker.sock"))
        self.note("le worker tourne sous le compte 10001", os.getuid() == 10001)
        try:
            v, _ = demander_filtre({"action": "version"})
            self.note(f"filtre joignable (Docker {v.get('docker')}, API {v.get('api')})", True)
        except FiltreInjoignable as e:
            self.note("filtre joignable", False, str(e))
            raise SystemExit("Filtre injoignable : arrêt de l'autotest.")

    def controles_scan(self) -> None:
        print("== Étape « scan »")
        a, b = self.a, self.b
        self.controle("compte 10001", "scan", 'test "$(id -u):$(id -g)" = 10001:10001')
        self.controle("écriture dans son dossier d'analyse", "scan", "echo x > out/essai && test -s out/essai")
        self.controle("fichiers créés en 0600 (masque 077)", "scan",
                      'touch out/masque && test "$(stat -c %a out/masque)" = 600')
        self.controle("système en lecture seule (/opt, /etc, /usr)", "scan",
                      "! touch /opt/essai 2>/dev/null && ! touch /etc/essai 2>/dev/null"
                      " && ! touch /usr/local/bin/essai 2>/dev/null")
        self.controle("autre analyse invisible", "scan",
                      f'test "$(ls -A /var/lib/asgor/jobs)" = "{a}" && test ! -e /var/lib/asgor/jobs/{b}')
        # Ces dossiers existent dans l'image (points de montage du worker et du site),
        # mais aucun volume n'y est monté chez l'étape : ils doivent être vides.
        self.controle("base, rapports, file, journaux, clé et sockets invisibles", "scan",
                      "for p in /var/lib/asgor/database /var/lib/asgor/reports /var/lib/asgor/file"
                      " /var/lib/asgor/logs /etc/asgor/secrets /run/asgor-controle;"
                      ' do if grep -q " $p " /proc/self/mountinfo; then echo "monté : $p"; exit 1; fi;'
                      ' if [ -n "$(ls -A "$p" 2>/dev/null)" ]; then echo "non vide : $p"; exit 1; fi; done'
                      " && test ! -e /var/run/docker.sock")
        self.controle("cache en lecture seule", "scan", "! touch /var/lib/asgor/cache/essai 2>/dev/null")
        self.controle("règles en lecture seule", "scan", "! touch /opt/asgor/regles/essai 2>/dev/null")
        # Le noyau crée aussi des interfaces de tunnel (gre0, sit0…), inactives et sans adresse.
        self.controle("aucune interface active sauf lo, aucune route", "scan",
                      "for i in /sys/class/net/*/operstate; do n=${i%/operstate}; n=${n##*/};"
                      ' [ "$n" = lo ] || [ "$(cat "$i")" = down ] || { echo "active : $n"; exit 1; }; done'
                      ' && test "$(wc -l < /proc/net/route)" -le 1')
        self.controle("aucun réseau (1.1.1.1:443)", "scan",
                      "python3 -I -c \"import socket,sys; s=socket.socket(); s.settimeout(3);"
                      " sys.exit(0 if s.connect_ex(('1.1.1.1', 443)) else 1)\"")
        self.controle("pas d'élévation de privilèges (NoNewPrivs, aucune capacité, pas de sudo)", "scan",
                      "grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status"
                      " && grep -q '^CapEff:[[:space:]]*0000000000000000' /proc/self/status"
                      " && grep -q '^CapBnd:[[:space:]]*0000000000000000' /proc/self/status"
                      " && ! command -v sudo")
        self.controle("limite de mémoire 4 Go, sans swap", "scan",
                      'test "$(cat /sys/fs/cgroup/memory.max)" = 4294967296'
                      ' && test "$(cat /sys/fs/cgroup/memory.swap.max)" = 0')
        self.controle("limite haute 6 Go seulement si demandée", "scan",
                      'test "$(cat /sys/fs/cgroup/memory.max)" = 6442450944', memoire_haute=True)
        self.controle("limite de 512 processus", "scan", 'test "$(cat /sys/fs/cgroup/pids.max)" = 512')
        self.controle("chaque outil démarre", "scan", "bash /opt/asgor/docker/tester-outils.sh")

    def controles_fetch(self) -> None:
        print("== Étape « fetch »")
        a, b = self.a, self.b
        py = "python3 -I -c "
        self.controle("git ls-remote https://github.com/gitleaks/gitleaks (par le proxy)", "fetch",
                      "git ls-remote https://github.com/gitleaks/gitleaks HEAD | grep -q HEAD")
        self.controle("nom hors liste refusé (www.example.com)", "fetch",
                      py + "\"import urllib.request,sys\ntry:\n urllib.request.urlopen('https://www.example.com', timeout=15)\n"
                      "except Exception: sys.exit(0)\nsys.exit(1)\"")
        self.controle("adresse IP directe refusée (https://1.1.1.1)", "fetch",
                      py + "\"import urllib.request,sys\ntry:\n urllib.request.urlopen('https://1.1.1.1', timeout=15)\n"
                      "except Exception: sys.exit(0)\nsys.exit(1)\"")
        self.controle("aucune sortie sans le proxy (1.1.1.1:443)", "fetch",
                      py + "\"import socket,sys; s=socket.socket(); s.settimeout(5);"
                      " sys.exit(0 if s.connect_ex(('1.1.1.1', 443)) else 1)\"")
        self.controle("aucune résolution DNS d'un nom externe", "fetch",
                      py + "\"import socket,sys\ntry:\n socket.getaddrinfo('example.com', 443)\n"
                      "except OSError: sys.exit(0)\nsys.exit(1)\"")
        self.controle("machine hôte injoignable (host.docker.internal, passerelle)", "fetch",
                      py + "\"import socket,sys\ncibles=[]\n"
                      "try: cibles.append(socket.gethostbyname('host.docker.internal'))\nexcept OSError: pass\n"
                      "for l in open('/proc/net/route').read().splitlines()[1:]:\n"
                      " c=l.split()\n if c[2]!='00000000': cibles.append(socket.inet_ntoa(bytes.fromhex(c[2])[::-1]))\n"
                      "for ip in cibles:\n for port in (22, 80, 443, 2375, 8000):\n"
                      "  s=socket.socket(); s.settimeout(2)\n  if s.connect_ex((ip, port))==0: print(ip, port); sys.exit(1)\n"
                      "sys.exit(0)\"")
        self.controle("le proxy refuse un autre port que 443", "fetch",
                      py + "\"import socket,sys; s=socket.create_connection(('proxy', 3128), 5);"
                      " s.sendall(b'CONNECT github.com:22 HTTP/1.1\\\\r\\\\n\\\\r\\\\n');"
                      " sys.exit(0 if s.recv(64).startswith(b'HTTP/1.1 403') else 1)\"")
        self.controle("file:// refusé par git", "fetch", "! git clone -q file:///etc src/etc 2>/dev/null")
        self.controle("autre analyse invisible", "fetch",
                      f'test "$(ls -A /var/lib/asgor/jobs)" = "{a}" && test ! -e /var/lib/asgor/jobs/{b}')
        self.controle("cache en écriture", "fetch",
                      f"touch /var/lib/asgor/cache/essai-{a} && rm /var/lib/asgor/cache/essai-{a}")

    def controles_filtre(self) -> None:
        print("== Filtre du socket Docker")
        base = {"action": "lancer", "profil": "scan", "analyse": self.a, "commande": ["true"],
                "memoire_haute": False}
        self.refus("champ inconnu (image)", dict(base, image="alpine:latest"))
        self.refus("montage demandé par le worker", dict(base, Mounts=[{"Source": "/", "Target": "/hote"}]))
        self.refus("mode privilégié demandé", dict(base, HostConfig={"Privileged": True}))
        self.refus("profil inconnu (réseau de l'hôte)", dict(base, profil="host"))
        self.refus("identifiant d'analyse invalide (../)", dict(base, analyse="../../../../etc"))
        self.refus("analyse inexistante", dict(base, analyse=secrets.token_hex(16)))
        self.refus("action exec", {"action": "exec", "conteneur": "0" * 64})
        self.refus("action build", {"action": "build"})
        self.refus("conteneur non créé par le filtre", {"action": "tuer", "conteneur": "0" * 64})


def main() -> int:
    return Autotest().lancer()


if __name__ == "__main__":
    sys.exit(main())
