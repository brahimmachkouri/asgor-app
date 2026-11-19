# ASGOR — image Docker (première étape : les outils d'analyse seuls).
# Construction : docker buildx build --platform linux/arm64 (ou linux/amd64) -t asgor:essai .
# Versions et sommes : versions-outils.json (une seule source, lue aussi par le playbook).
# Pas de directive « # syntax= » : elle téléchargerait une image de construction non épinglée.

# Image de base épinglée par empreinte (publiée depuis au moins 14 jours). Doit être
# égale à « image_ubuntu » de versions-outils.json : vérifié dans l'étape de téléchargement.
ARG IMAGE_UBUNTU=ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db

# ------------------------------------------------------------------ socle commun
FROM ${IMAGE_UBUNTU} AS socle
# Instantané daté de l'archive Ubuntu : mêmes paquets à chaque construction.
ARG INSTANTANE_APT=20261105T000000Z
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
# 1. Certificats depuis l'archive courante (paquet signé, vérifié par apt) : l'instantané
#    n'est servi qu'en HTTPS. 2. Toutes les sources basculées sur l'instantané.
# 3. Certificats réinstallés dans la version de l'instantané.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && sed -i -E "s#^URIs: http://(archive|security|ports)\.ubuntu\.com/ubuntu(-ports)?/#URIs: https://snapshot.ubuntu.com/ubuntu/${INSTANTANE_APT}/#" \
      /etc/apt/sources.list.d/ubuntu.sources \
 && ! grep -E '^URIs:' /etc/apt/sources.list.d/ubuntu.sources | grep -v "snapshot.ubuntu.com/ubuntu/${INSTANTANE_APT}/" \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get update \
 && apt-get install -y --no-install-recommends --allow-downgrades \
      "ca-certificates=$(apt-cache madison ca-certificates | awk 'NR==1 {print $3}')" \
 && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------- téléchargement des binaires
FROM socle AS telechargement
ARG IMAGE_UBUNTU
ARG INSTANTANE_APT
ARG TARGETPLATFORM
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl jq \
 && rm -rf /var/lib/apt/lists/*
COPY versions-outils.json /construction/versions-outils.json
COPY docker/installer-binaires.sh /construction/installer-binaires.sh
# Image de base et instantané : ceux de versions-outils.json, sinon arrêt.
RUN test "$(jq -r .image_ubuntu /construction/versions-outils.json)" = "${IMAGE_UBUNTU}" \
 && test "$(jq -r .instantane_apt /construction/versions-outils.json)" = "${INSTANTANE_APT}" \
 && bash /construction/installer-binaires.sh /construction/versions-outils.json "${TARGETPLATFORM}" /sortie

# ------------------------------------------------------------- image finale
FROM socle AS final
ARG VERSION_ASGOR=developpement
ARG COMMIT_ASGOR=inconnu
LABEL org.opencontainers.image.source="https://github.com/brahimmachkouri/asgor" \
      org.opencontainers.image.title="ASGOR" \
      org.opencontainers.image.description="Automated Security Grading Of Repositories" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION_ASGOR}" \
      org.opencontainers.image.revision="${COMMIT_ASGOR}"

# Mêmes paquets que la VM (asgor-ansible/asgor.yml), sans ce qui ne sert qu'à la VM
# (SSH, UFW, mises à jour automatiques, QEMU, bubblewrap).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl git unzip python3 python3-venv \
      php-cli php-xml php-mbstring php-curl php-zip composer \
 && rm -rf /var/lib/apt/lists/*

# Outils Python : un venv par outil, outil + dépendances épinglés avec sommes SHA256.
COPY asgor-ansible/files/outils-python/ /opt/asgor/venvs/listes/
RUN for outil in bandit pip-audit; do \
      python3 -m venv /opt/asgor/venvs/$outil \
   && /opt/asgor/venvs/$outil/bin/python -m pip install --disable-pip-version-check --no-input \
        --no-cache-dir --require-hashes --no-deps --only-binary=:all: \
        -r /opt/asgor/venvs/listes/$outil.txt \
   && /opt/asgor/venvs/$outil/bin/python -m pip check \
   && ln -s /opt/asgor/venvs/$outil/bin/$outil /usr/local/bin/$outil ; \
    done

COPY --from=telechargement /sortie/ /usr/local/bin/

# Comptes : étapes d'analyse et worker (10001), service web (10002), filtre du socket
# Docker (10003). Aucun conteneur en root.
RUN groupadd --gid 10001 asgor && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin asgor \
 && groupadd --gid 10002 asgor-web && useradd --uid 10002 --gid 10002 --no-create-home --shell /usr/sbin/nologin asgor-web \
 && groupadd --gid 10003 asgor-filtre && useradd --uid 10003 --gid 10003 --no-create-home --shell /usr/sbin/nologin asgor-filtre

# Points de montage des volumes, avec leur propriétaire et leurs droits : Docker les
# recopie dans un volume nommé vide au premier montage.
RUN install -d -o 10001 -g 10001 -m 0700 /var/lib/asgor/jobs \
 && install -d -o 10001 -g 10001 -m 0755 /var/lib/asgor/cache /var/lib/asgor/cache/composer \
      /var/lib/asgor/cache/trivy /var/lib/asgor/cache/osv /opt/asgor/regles \
 && install -d -o 10003 -g 10001 -m 0750 /run/asgor-controle \
 && install -d -o 10001 -g 10002 -m 2750 /var/lib/asgor/database /var/lib/asgor/reports \
 && install -d -o 10001 -g 10001 -m 0700 /var/lib/asgor/logs /etc/asgor/secrets \
 && install -d -o 10002 -g 10002 -m 2770 /var/lib/asgor/file

# Service web : dépendances épinglées avec sommes SHA256, comme sur la VM.
COPY web/requirements.txt /opt/asgor/web/requirements.txt
RUN python3 -m venv /opt/asgor/venvs/web \
 && /opt/asgor/venvs/web/bin/python -m pip install --disable-pip-version-check --no-input \
      --no-cache-dir --require-hashes --no-deps --only-binary=:all: -r /opt/asgor/web/requirements.txt \
 && /opt/asgor/venvs/web/bin/python -m pip check

# Moteur d'analyse, worker, filtre du socket Docker, proxy de sortie, autotest, service web.
COPY moteur/asgor_moteur/ /opt/asgor/moteur/asgor_moteur/
COPY moteur/conf/ /opt/asgor/moteur/conf/
COPY web/asgor_web/ /opt/asgor/web/asgor_web/
COPY --chmod=0755 moteur/bin/asgor-worker moteur/bin/asgor-scan web/bin/asgor-web /usr/local/bin/
ENV PYTHONPATH=/opt/asgor/moteur PYTHONDONTWRITEBYTECODE=1 ASGOR_LANCEUR=docker

# Versions affichées par le service web et recopiées dans chaque rapport,
# relevées sur les outils de l'image et comparées à versions-outils.json.
COPY versions-outils.json /opt/asgor/versions-outils.json
COPY docker/ecrire-outils-json.sh docker/tester-outils.sh /opt/asgor/docker/
RUN HOME=/tmp bash /opt/asgor/docker/ecrire-outils-json.sh /opt/asgor/versions-outils.json /opt/asgor/outils.json \
 && rm -rf /tmp/* /tmp/.[!.]*

USER 10001:10001
WORKDIR /tmp
CMD ["bash", "/opt/asgor/docker/tester-outils.sh"]
