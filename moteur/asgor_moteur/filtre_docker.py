"""Filtre du socket Docker (image Docker).

Seul conteneur à voir /var/run/docker.sock. Le worker ne parle jamais à Docker : il
envoie au filtre, par un socket Unix (volume asgor-controle), une petite demande ASGOR
d'une ligne JSON. Le filtre la vérifie champ par champ, puis écrit LUI-MÊME toute la
configuration Docker de l'étape avec des valeurs fixes. Le worker ne choisit ni
l'image, ni le compte, ni les montages, ni le réseau, ni les limites.

Demandes acceptées (tout champ inconnu fait refuser la demande) :

  {"action": "version"}
  {"action": "lancer", "profil": "fetch"|"scan", "analyse": "<32 hex>",
   "commande": ["outil", "arg", …], "memoire_haute": false}
  {"action": "regles"}   installation des règles Semgrep (commande fixée par le filtre)
  {"action": "attendre"|"tuer"|"journaux"|"supprimer", "conteneur": "<id>"}

Les quatre dernières ne valent que pour un conteneur créé par ce filtre. Tout le reste
de l'API Docker (exec, build, pull, volumes, réseaux, images…) est inaccessible.
Chaque refus est journalisé.

Bibliothèque standard seulement.
"""

import http.client
import json
import os
import re
import socket
import socketserver
import struct
import sys
import threading
import time
import urllib.parse

SOCKET_DOCKER = "/var/run/docker.sock"
SOCKET_FILTRE = "/run/asgor-controle/filtre.sock"
# 1.45 : première version de l'API avec les montages de sous-dossier (Docker Engine 26).
API = "v1.45"
VERSION_API_MIN = (1, 45)

UID_ETAPES = 10001          # compte des étapes (et du worker, seul client accepté)
TAILLE_MAX_DEMANDE = 65536
TAILLE_MAX_JOURNAL = 20 * 1024 * 1024
ARGUMENTS_MAX = 512
TAILLE_MAX_ARGUMENT = 8192

ID_ANALYSE = re.compile(r"^[0-9a-f]{32}$")
ID_CONTENEUR = re.compile(r"^[0-9a-f]{64}$")
PROFILS = ("fetch", "scan")
CHAMPS = {
    "version": {"action"},
    "regles": {"action"},
    "lancer": {"action", "profil", "analyse", "commande", "memoire_haute"},
    "attendre": {"action", "conteneur"},
    "tuer": {"action", "conteneur"},
    "journaux": {"action", "conteneur"},
    "supprimer": {"action", "conteneur"},
}

# Chemins vus par les étapes : les mêmes que sur la VM (asgor-sandbox).
ANALYSES = "/var/lib/asgor/jobs"
CACHE = "/var/lib/asgor/cache"
REGLES = "/opt/asgor/regles"
ETIQUETTE = "asgor.etape"
VERSIONS = "/opt/asgor/versions-outils.json"   # dans l'image : commit et somme des règles


class Refus(Exception):
    """Demande refusée par le filtre (journalisée, renvoyée au worker)."""


class ErreurDocker(Exception):
    """Docker a répondu par une erreur."""


def _entier(nom: str, defaut: int) -> int:
    return int(os.environ.get(nom, defaut))


class Reglages:
    """Valeurs fixées au démarrage du filtre (compose.yaml), jamais par le worker."""

    def __init__(self, env=os.environ):
        self.volume_analyses = env.get("ASGOR_VOLUME_ANALYSES", "asgor-analyses")
        self.volume_cache = env.get("ASGOR_VOLUME_CACHE", "asgor-cache")
        self.volume_regles = env.get("ASGOR_VOLUME_REGLES", "asgor-regles")
        self.reseau_fetch = env.get("ASGOR_RESEAU_FETCH", "asgor-fetch")
        self.proxy = env.get("ASGOR_PROXY", "http://proxy:3128")
        self.memoire = int(env.get("ASGOR_MEMOIRE", 4 * 1024**3))
        self.memoire_haute = int(env.get("ASGOR_MEMOIRE_HAUTE", 6 * 1024**3))
        # 3 processeurs comme sur la VM, sans dépasser ceux de la machine Docker.
        self.processeurs = min(float(env.get("ASGOR_PROCESSEURS", 3)), float(os.cpu_count() or 1))
        self.processus_max = int(env.get("ASGOR_PROCESSUS_MAX", 512))
        self.taille_tmp = int(env.get("ASGOR_TAILLE_TMP", 512 * 1024**2))


def verifier_demande(demande) -> dict:
    """Vérifie une demande du worker ; renvoie la demande ou lève Refus."""
    if not isinstance(demande, dict):
        raise Refus("demande : objet JSON attendu")
    action = demande.get("action")
    if action not in CHAMPS:
        raise Refus(f"action refusée : {str(action)[:40]!r}")
    if set(demande) != CHAMPS[action]:
        raise Refus(f"{action} : champs attendus {sorted(CHAMPS[action])}, reçus {sorted(map(str, demande))[:10]}")
    if action == "lancer":
        if demande["profil"] not in PROFILS:
            raise Refus(f"profil refusé : {str(demande['profil'])[:20]!r}")
        if not isinstance(demande["analyse"], str) or not ID_ANALYSE.match(demande["analyse"]):
            raise Refus("identifiant d'analyse invalide (32 caractères hexadécimaux)")
        if demande["memoire_haute"] is not True and demande["memoire_haute"] is not False:
            raise Refus("memoire_haute : booléen attendu")
        commande = demande["commande"]
        if (not isinstance(commande, list) or not commande or len(commande) > ARGUMENTS_MAX
                or not all(isinstance(a, str) for a in commande)):
            raise Refus("commande : liste de chaînes attendue")
        if any(len(a) > TAILLE_MAX_ARGUMENT or "\x00" in a for a in commande) or not commande[0]:
            raise Refus("commande : argument vide, trop long ou avec un caractère nul")
    elif action not in ("version", "regles"):
        if not isinstance(demande["conteneur"], str) or not ID_CONTENEUR.match(demande["conteneur"]):
            raise Refus("identifiant de conteneur invalide")
    return demande


def environnement(profil: str, analyse: str, reglages: Reglages) -> list:
    """Variables des étapes : celles d'asgor-sandbox, plus le proxy en fetch."""
    dossier = f"{ANALYSES}/{analyse}"
    variables = {
        "HOME": f"{dossier}/home",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_SEND_METRICS": "off",
        "COMPOSER_HOME": f"{CACHE}/composer",
        "COMPOSER_NO_INTERACTION": "1",
        "COMPOSER_ALLOW_SUPERUSER": "0",
        "TRIVY_CACHE_DIR": f"{CACHE}/trivy",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    if profil == "fetch":
        for nom in ("HTTPS_PROXY", "https_proxy"):
            variables[nom] = reglages.proxy
        variables["NO_PROXY"] = variables["no_proxy"] = ""
    else:
        variables["COMPOSER_DISABLE_NETWORK"] = "1"
    return [f"{k}={v}" for k, v in variables.items()]


def configuration(demande: dict, image: str, reglages: Reglages) -> dict:
    """Configuration Docker complète d'une étape, écrite par le filtre seul."""
    profil, analyse = demande["profil"], demande["analyse"]
    memoire = reglages.memoire_haute if demande["memoire_haute"] else reglages.memoire
    dossier = f"{ANALYSES}/{analyse}"
    montages = [
        # Seul le sous-dossier de cette analyse est visible.
        {"Type": "volume", "Source": reglages.volume_analyses, "Target": dossier,
         "ReadOnly": False, "VolumeOptions": {"NoCopy": True, "Subpath": analyse}},
        {"Type": "volume", "Source": reglages.volume_cache, "Target": CACHE,
         "ReadOnly": profil == "scan", "VolumeOptions": {"NoCopy": True}},
        {"Type": "volume", "Source": reglages.volume_regles, "Target": REGLES,
         "ReadOnly": True, "VolumeOptions": {"NoCopy": True}},
    ]
    return {
        "Image": image,
        # Masque 077 comme asgor-sandbox (UMask=0077) : Docker n'a pas d'option pour cela.
        "Cmd": ["/bin/sh", "-c", 'umask 077 && exec "$@"', "asgor-etape", *demande["commande"]],
        "Entrypoint": [],
        "User": f"{UID_ETAPES}:{UID_ETAPES}",
        "WorkingDir": dossier,
        "Env": environnement(profil, analyse, reglages),
        "Labels": {ETIQUETTE: profil, "asgor.analyse": analyse},
        "Hostname": "asgor-etape",
        "AttachStdin": False, "OpenStdin": False, "Tty": False,
        "NetworkDisabled": profil == "scan",
        "HostConfig": {
            "Mounts": montages,
            "Binds": [], "VolumesFrom": [], "Links": [], "Devices": [], "DeviceRequests": [],
            "NetworkMode": "none" if profil == "scan" else reglages.reseau_fetch,
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"], "CapAdd": [],
            "SecurityOpt": ["no-new-privileges:true"],
            "IpcMode": "private",
            "Memory": memoire, "MemorySwap": memoire,
            "NanoCpus": int(reglages.processeurs * 1e9),
            "PidsLimit": reglages.processus_max,
            "Tmpfs": {"/tmp": f"rw,nosuid,nodev,size={reglages.taille_tmp}"},
            "Ulimits": [{"Name": "core", "Soft": 0, "Hard": 0}],
            "LogConfig": {"Type": "json-file", "Config": {"max-size": "20m", "max-file": "1"}},
            "RestartPolicy": {"Name": "no"},
            "AutoRemove": False,
            "Init": False,
            "OomKillDisable": False,
            "PublishAllPorts": False, "PortBindings": {},
            "ExtraHosts": [],
        },
    }


def configuration_regles(image: str, reglages: Reglages, versions: str = VERSIONS) -> dict:
    """Étape d'installation des règles Semgrep : seul volume monté, asgor-regles (écriture).

    Commit et somme lus dans l'image (versions-outils.json), commande fixée ici :
    le worker ne choisit rien."""
    with open(versions, encoding="utf-8") as f:
        regles = json.load(f)["regles_semgrep"]
    commit, somme = regles["commit"], regles["sha256"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", somme):
        raise Refus("versions-outils.json : commit ou somme des règles invalide")
    corps = configuration({"profil": "fetch", "analyse": "0" * 32, "commande": ["true"],
                           "memoire_haute": False}, image, reglages)
    corps["Cmd"] = ["python3", "-m", "asgor_moteur.regles", commit, somme]
    corps["WorkingDir"] = "/tmp"
    corps["Labels"] = {ETIQUETTE: "regles"}
    corps["Env"] = [v for v in corps["Env"] if not v.startswith(("HOME=", "COMPOSER_", "TRIVY_"))] + ["HOME=/tmp"]
    corps["HostConfig"]["Mounts"] = [
        {"Type": "volume", "Source": reglages.volume_regles, "Target": REGLES,
         "ReadOnly": False, "VolumeOptions": {"NoCopy": True}}]
    return corps


def separer_journal(flux: bytes) -> bytes:
    """Journal Docker sans terminal : trames [flux, 0, 0, 0, taille sur 4 octets]."""
    sortie = bytearray()
    i = 0
    while i + 8 <= len(flux):
        taille = struct.unpack(">I", flux[i + 4:i + 8])[0]
        sortie += flux[i + 8:i + 8 + taille]
        i += 8 + taille
    return bytes(sortie)


class _ConnexionUnix(http.client.HTTPConnection):
    def __init__(self, chemin: str, delai: float):
        super().__init__("localhost", timeout=delai)
        self.chemin = chemin

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.chemin)


class Docker:
    """Client minimal de l'API Docker, par le socket Unix."""

    def __init__(self, chemin: str = SOCKET_DOCKER):
        self.chemin = chemin

    def requete(self, methode: str, chemin: str, corps=None, delai: float = 60,
                taille_max: int = 1024 * 1024) -> tuple:
        connexion = _ConnexionUnix(self.chemin, delai)
        try:
            entetes = {"Host": "docker"}
            donnees = None
            if corps is not None:
                donnees = json.dumps(corps).encode()
                entetes["Content-Type"] = "application/json"
            connexion.request(methode, f"/{API}{chemin}", body=donnees, headers=entetes)
            reponse = connexion.getresponse()
            contenu = reponse.read(taille_max + 1)
            return reponse.status, contenu[:taille_max]
        finally:
            connexion.close()

    def json(self, methode: str, chemin: str, corps=None, attendus=(200,), **options):
        statut, contenu = self.requete(methode, chemin, corps, **options)
        if statut not in attendus:
            try:
                message = json.loads(contenu).get("message", "")
            except (ValueError, AttributeError):
                message = contenu[:200].decode("utf-8", "replace")
            raise ErreurDocker(f"Docker {statut} : {message[:300]}")
        return json.loads(contenu) if contenu.strip() else None


def journal(message: str) -> None:
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} filtre : {message}", file=sys.stderr, flush=True)


class Filtre:
    def __init__(self, docker: Docker, reglages: Reglages, image: str):
        self.docker = docker
        self.reglages = reglages
        self.image = image
        self.conteneurs = {}      # identifiant -> (profil, analyse), créés par ce filtre
        self.verrou = threading.Lock()

    # ------------------------------------------------------------------ actions
    def traiter(self, demande: dict) -> tuple:
        """Renvoie (réponse JSON, octets bruts à envoyer après la réponse)."""
        action = demande["action"]
        if action == "version":
            v = self.docker.json("GET", "/version")
            return {"ok": True, "docker": v.get("Version"), "api": v.get("ApiVersion"),
                    "image": self.image}, b""
        if action == "lancer":
            return self._lancer(demande), b""
        if action == "regles":
            return self._creer_et_demarrer(configuration_regles(self.image, self.reglages),
                                           ("regles", None), "installation des règles Semgrep"), b""
        conteneur = demande["conteneur"]
        self._verifier_proprietaire(conteneur)
        if action == "attendre":
            etat = self.docker.json("GET", f"/containers/{conteneur}/json")["State"]
            termine = etat.get("Status") in ("exited", "dead")
            return {"ok": True, "termine": termine,
                    "code": etat.get("ExitCode") if termine else None,
                    "memoire_depassee": bool(etat.get("OOMKilled"))}, b""
        if action == "tuer":
            self.docker.json("POST", f"/containers/{conteneur}/kill", attendus=(204, 409))
            return {"ok": True}, b""
        if action == "journaux":
            statut, flux = self.docker.requete(
                "GET", f"/containers/{conteneur}/logs?stdout=1&stderr=1",
                taille_max=TAILLE_MAX_JOURNAL + 1024 * 1024, delai=120)
            if statut != 200:
                raise ErreurDocker(f"Docker {statut} : journal illisible")
            texte = separer_journal(flux)[:TAILLE_MAX_JOURNAL]
            return {"ok": True, "taille": len(texte)}, texte
        if action == "supprimer":
            self.docker.json("DELETE", f"/containers/{conteneur}?force=1", attendus=(204, 404))
            with self.verrou:
                self.conteneurs.pop(conteneur, None)
            return {"ok": True}, b""
        raise Refus(f"action refusée : {action}")  # inatteignable (verifier_demande)

    def _lancer(self, demande: dict) -> dict:
        return self._creer_et_demarrer(
            configuration(demande, self.image, self.reglages), (demande["profil"], demande["analyse"]),
            f"étape {demande['profil']} pour l'analyse {demande['analyse']} : "
            f"{' '.join(demande['commande'])[:200]}")

    def _creer_et_demarrer(self, corps: dict, cle: tuple, libelle: str) -> dict:
        cree = self.docker.json("POST", "/containers/create", corps, attendus=(201,))
        conteneur = cree["Id"]
        with self.verrou:
            self.conteneurs[conteneur] = cle
        try:
            self.docker.json("POST", f"/containers/{conteneur}/start", attendus=(204,))
        except ErreurDocker:
            self.docker.json("DELETE", f"/containers/{conteneur}?force=1", attendus=(204, 404))
            with self.verrou:
                self.conteneurs.pop(conteneur, None)
            raise
        journal(f"lancé ({conteneur[:12]}) : {libelle}")
        return {"ok": True, "conteneur": conteneur}

    def _verifier_proprietaire(self, conteneur: str) -> None:
        with self.verrou:
            connu = conteneur in self.conteneurs
        if not connu:
            raise Refus(f"conteneur {conteneur[:12]} non créé par le filtre")
        infos = self.docker.json("GET", f"/containers/{conteneur}/json", attendus=(200, 404))
        if infos is None or ETIQUETTE not in (infos.get("Config", {}).get("Labels") or {}):
            raise Refus(f"conteneur {conteneur[:12]} sans l'étiquette {ETIQUETTE}")

    def nettoyer_anciennes_etapes(self) -> None:
        """Étapes restées d'un précédent démarrage du filtre : arrêtées et supprimées."""
        filtre = urllib.parse.quote(json.dumps({"label": [ETIQUETTE]}))
        for c in self.docker.json("GET", f"/containers/json?all=1&filters={filtre}") or []:
            self.docker.json("DELETE", f"/containers/{c['Id']}?force=1", attendus=(204, 404))
            journal(f"ancienne étape supprimée : {c['Id'][:12]}")


def image_en_cours(docker: Docker) -> str:
    """Empreinte de l'image du filtre lui-même : les étapes utilisent exactement celle-ci."""
    nom = socket.gethostname()
    infos = docker.json("GET", f"/containers/{urllib.parse.quote(nom)}/json")
    image = infos.get("Image", "")
    if not re.match(r"^sha256:[0-9a-f]{64}$", image):
        raise SystemExit(f"filtre : image du conteneur {nom} illisible")
    return image


def uid_du_client(connexion: socket.socket) -> int:
    donnees = connexion.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", donnees)[1]


class Gestionnaire(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        filtre = self.server.filtre
        self.connection.settimeout(30)
        try:
            uid = uid_du_client(self.connection)
            if uid != UID_ETAPES:
                raise Refus(f"client refusé (compte {uid})")
            ligne = self.rfile.readline(TAILLE_MAX_DEMANDE + 1)
            if len(ligne) > TAILLE_MAX_DEMANDE or not ligne.endswith(b"\n"):
                raise Refus("demande trop longue ou incomplète")
            try:
                demande = json.loads(ligne)
            except ValueError:
                raise Refus("demande : JSON invalide")
            reponse, brut = filtre.traiter(verifier_demande(demande))
        except Refus as r:
            journal(f"REFUS : {r}")
            reponse, brut = {"ok": False, "refus": str(r)}, b""
        except (ErreurDocker, OSError, ValueError, KeyError) as e:
            journal(f"erreur : {e}")
            reponse, brut = {"ok": False, "erreur": str(e)[:500]}, b""
        try:
            self.wfile.write(json.dumps(reponse).encode() + b"\n" + brut)
        except OSError:
            pass


class Serveur(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, chemin: str, filtre: Filtre):
        self.filtre = filtre
        if os.path.exists(chemin):
            os.unlink(chemin)
        super().__init__(chemin, Gestionnaire)
        # Le dossier (volume asgor-controle) n'est monté que chez le worker et le filtre ;
        # le compte du client est en plus vérifié à chaque connexion (SO_PEERCRED).
        os.chmod(chemin, 0o666)


def main() -> int:
    docker = Docker(os.environ.get("ASGOR_SOCKET_DOCKER", SOCKET_DOCKER))
    version = docker.json("GET", "/version")
    api = tuple(int(x) for x in str(version.get("ApiVersion", "0.0")).split(".")[:2])
    if api < VERSION_API_MIN:
        raise SystemExit(f"filtre : Docker {version.get('Version')} trop ancien "
                         f"(API {version.get('ApiVersion')}, il faut Docker Engine 26 ou plus)")
    filtre = Filtre(docker, Reglages(), image_en_cours(docker))
    filtre.nettoyer_anciennes_etapes()
    chemin = os.environ.get("ASGOR_SOCKET_FILTRE", SOCKET_FILTRE)
    with Serveur(chemin, filtre) as serveur:
        journal(f"prêt : Docker {version.get('Version')}, image {filtre.image[:19]}…, socket {chemin}")
        serveur.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
