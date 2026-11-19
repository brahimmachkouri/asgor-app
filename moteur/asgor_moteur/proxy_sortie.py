"""Proxy de sortie des étapes « fetch » (image Docker).

Les étapes « fetch » sont sur un réseau Docker interne, sans route vers l'extérieur.
Leur seule sortie est ce proxy, qui n'accepte que :

- la méthode CONNECT, vers le port 443 seulement ;
- un nom de la liste des domaines autorisés (moteur/conf/proxy-domaines.txt), écrit
  exactement (pas d'adresse IP, pas de joker) ;
- un nom dont TOUTES les adresses sont publiques (ipaddress.is_global) : un nom
  autorisé ne peut pas mener au réseau local, à la machine du développeur ou au
  réseau de Docker.

Le proxy se connecte à l'adresse qu'il vient de vérifier, sans nouvelle résolution
DNS. Chaque refus est journalisé (nom demandé, adresse de l'étape, raison) : c'est
ainsi qu'on complète la liste.

Bibliothèque standard seulement.
"""

import ipaddress
import os
import select
import socket
import socketserver
import sys
import threading
import time

PORT = 3128
LISTE = "/opt/asgor/moteur/conf/proxy-domaines.txt"
TAILLE_MAX_ENTETE = 8192        # requête CONNECT et en-têtes
DELAI_ENTETE = 10               # secondes pour recevoir la requête
DELAI_CONNEXION = 15            # secondes pour joindre le serveur distant
DELAI_INACTIVITE = 300          # secondes sans aucun échange : tunnel fermé
CONNEXIONS_MAX = 64


class Refus(Exception):
    """Demande refusée : code HTTP et raison (journalisée, renvoyée à l'étape)."""

    def __init__(self, code: int, raison: str):
        super().__init__(raison)
        self.code = code
        self.raison = raison


def lire_liste(chemin: str) -> frozenset:
    """Noms autorisés : un par ligne, « # » pour un commentaire."""
    noms = set()
    with open(chemin, encoding="utf-8") as f:
        for ligne in f:
            nom = ligne.split("#", 1)[0].strip().lower()
            if nom:
                if not est_nom_valide(nom):
                    raise ValueError(f"nom invalide dans {chemin} : {nom!r}")
                noms.add(nom)
    return frozenset(noms)


def est_nom_valide(nom: str) -> bool:
    """Nom DNS ordinaire : lettres, chiffres, tirets, points ; pas d'adresse IP."""
    if not nom or len(nom) > 253 or nom.endswith(".") or nom.startswith("."):
        return False
    try:
        ipaddress.ip_address(nom)
        return False
    except ValueError:
        pass
    try:
        # Formes que le système lit comme une adresse IPv4 : « 0x7f000001 »,
        # « 2130706433 », « 127.1 », « 0177.0.0.1 »…
        socket.inet_aton(nom)
        return False
    except OSError:
        pass
    for partie in nom.split("."):
        if not partie or len(partie) > 63 or partie.startswith("-") or partie.endswith("-"):
            return False
        if not all(c.isascii() and (c.isalnum() or c == "-") for c in partie):
            return False
    return not nom.replace(".", "").isdigit()


def est_publique(adresse: str) -> bool:
    ip = ipaddress.ip_address(adresse)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def analyser_demande(entete: bytes) -> str:
    """Renvoie le nom demandé si la requête est un CONNECT acceptable vers le port 443."""
    try:
        texte = entete.decode("ascii")
    except UnicodeDecodeError:
        raise Refus(400, "requête illisible")
    premiere = texte.split("\r\n", 1)[0]
    parties = premiere.split(" ")
    if len(parties) != 3 or not parties[2].startswith("HTTP/1."):
        raise Refus(400, "requête illisible")
    methode, cible, _ = parties
    if methode != "CONNECT":
        raise Refus(405, f"méthode {methode[:16]} refusée (CONNECT seulement)")
    if cible.startswith("["):
        raise Refus(403, "adresse IP refusée")
    nom, deux_points, port = cible.rpartition(":")
    if not deux_points or port != "443":
        raise Refus(403, f"port refusé ({cible[:80]}) : 443 seulement")
    nom = nom.lower()
    if not est_nom_valide(nom):
        raise Refus(403, f"nom refusé ({nom[:80]}) : adresse IP ou nom invalide")
    return nom


def resoudre(nom: str, resolveur=socket.getaddrinfo) -> list:
    """Adresses du nom ; refus si l'une d'elles n'est pas publique."""
    try:
        resultats = resolveur(nom, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise Refus(502, f"{nom} : nom introuvable")
    adresses = []
    for famille, _, _, _, adresse in resultats:
        if famille not in (socket.AF_INET, socket.AF_INET6):
            continue
        if not est_publique(adresse[0]):
            raise Refus(403, f"{nom} mène à une adresse non publique ({adresse[0]})")
        if (famille, adresse) not in adresses:
            adresses.append((famille, adresse))
    if not adresses:
        raise Refus(502, f"{nom} : aucune adresse")
    return adresses


def connecter(adresses: list) -> socket.socket:
    derniere = None
    for famille, adresse in adresses:
        s = socket.socket(famille, socket.SOCK_STREAM)
        s.settimeout(DELAI_CONNEXION)
        try:
            s.connect(adresse)
            return s
        except OSError as e:
            derniere = e
            s.close()
    raise Refus(502, f"connexion impossible ({derniere})")


def relayer(a: socket.socket, b: socket.socket) -> None:
    a.setblocking(True)
    b.setblocking(True)
    a.settimeout(None)
    b.settimeout(None)
    paires = {a: b, b: a}
    ouverts = [a, b]
    while ouverts:
        lisibles, _, _ = select.select(ouverts, [], [], DELAI_INACTIVITE)
        if not lisibles:
            return  # inactivité
        for s in lisibles:
            try:
                donnees = s.recv(65536)
            except OSError:
                return
            if not donnees:
                # Fin d'un côté : on la transmet, puis on attend la fin de l'autre.
                try:
                    paires[s].shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                ouverts.remove(s)
                continue
            try:
                paires[s].sendall(donnees)
            except OSError:
                return


def journal(message: str) -> None:
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} proxy : {message}", file=sys.stderr, flush=True)


class Gestionnaire(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        origine = self.client_address[0]
        if not self.server.places.acquire(blocking=False):
            journal(f"refus {origine} : trop de connexions")
            client.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
            return
        distant = None
        try:
            entete = self._lire_entete(client)
            nom = analyser_demande(entete)
            if nom not in self.server.liste:
                raise Refus(403, f"{nom} n'est pas dans la liste des domaines autorisés")
            distant = connecter(resoudre(nom, self.server.resolveur))
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            journal(f"tunnel {origine} -> {nom} ({distant.getpeername()[0]})")
            relayer(client, distant)
        except Refus as r:
            journal(f"refus {origine} : {r.raison}")
            try:
                client.sendall(f"HTTP/1.1 {r.code} ASGOR\r\nConnection: close\r\n"
                               f"Content-Type: text/plain; charset=utf-8\r\n\r\n"
                               f"ASGOR : {r.raison}\n".encode())
            except OSError:
                pass
        except OSError as e:
            journal(f"erreur {origine} : {e}")
        finally:
            if distant is not None:
                distant.close()
            self.server.places.release()

    @staticmethod
    def _lire_entete(client: socket.socket) -> bytes:
        client.settimeout(DELAI_ENTETE)
        recu = b""
        while b"\r\n\r\n" not in recu:
            if len(recu) > TAILLE_MAX_ENTETE:
                raise Refus(431, "requête trop longue")
            try:
                morceau = client.recv(1024)
            except socket.timeout:
                raise Refus(408, "requête incomplète")
            if not morceau:
                raise Refus(400, "connexion fermée avant la requête")
            recu += morceau
        entete, _, reste = recu.partition(b"\r\n\r\n")
        if len(entete) > TAILLE_MAX_ENTETE:
            raise Refus(431, "requête trop longue")
        if reste:
            # Rien ne doit suivre un CONNECT avant la réponse du proxy.
            raise Refus(400, "données inattendues après la requête")
        return entete


class Serveur(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, adresse, liste: frozenset, resolveur=socket.getaddrinfo):
        self.liste = liste
        self.resolveur = resolveur
        self.places = threading.BoundedSemaphore(CONNEXIONS_MAX)
        super().__init__(adresse, Gestionnaire)


def main() -> int:
    chemin = os.environ.get("ASGOR_PROXY_LISTE", LISTE)
    liste = lire_liste(chemin)
    port = int(os.environ.get("ASGOR_PROXY_PORT", PORT))
    with Serveur(("0.0.0.0", port), liste) as serveur:
        journal(f"écoute sur le port {port}, {len(liste)} domaines autorisés")
        serveur.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
