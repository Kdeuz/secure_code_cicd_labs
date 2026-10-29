# Rapport d'incident : Faille Supply Chain sur `requests`

**Date :** 29 octobre 2026

**Auteur :** Équipe DevOps / SecOps MiniShop

**Statut :** Résolu

**Sévérité :** Critique

## 1. Détection

L'alerte est tombée via le scan automatique du pipeline CI/CD (`security.yml`) lors d'un push, ainsi que par une alerte Dependabot signalant une version compromise de la bibliothèque `requests`.

### Commandes exécutées pour confirmer

```
# Vérification des vulnérabilités connues dans les dépendances verrouillées
pip-audit -r app/requirements.txt

# Scan global du dépôt avec Trivy
trivy fs app/
```

## 2. Évaluation de l'exposition

L'objectif était de déterminer si la version vérolée était réellement installée dans l'environnement virtuel, présente dans le conteneur Docker ou déployée en prod, et de vérifier quels fichiers ou variables d'environnement elle aurait pu lire.

### Commandes d'investigation

```
# 1. Vérifier la version exacte installée et verrouillée
grep -i "requests==" app/requirements.txt
pip show requests

# 2. Inspecter le SBOM pour voir l'arbre de dépendances
grep -A 5 -i "requests" sbom.json

# 3. Vérifier où requests est utilisé dans le code source
grep -rn "requests" app/

# 4. Tracer le commit d'introduction de cette version
git log -S "requests" -- app/requirements.txt
```

## 3. Confinement immédiat

Pour éviter toute fuite de données ou communication avec un serveur C2 (Command & Control), nous avons immédiatement coupé l'exécution du service et isolé l'environnement.

### Commandes de confinement

```
# 1. Arrêter le conteneur en cours d'exécution
docker stop minishop-app

# 2. Supprimer l'environnement virtuel local compromis
deactivate
rm -rf .venv/

# 3. Bloquer temporairement les déploiements automatiques sur main
git checkout -b incident/containment-requests
```

## 4. Correction et Remédiation

Nous avons mis à jour la dépendance vers une version saine, régénéré le `requirements.txt` avec les nouveaux hashes SHA-256 et reconstruit l'image Docker.

### Commandes de correction

```
# 1. Reconstitution d'un venv propre
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip pip-tools pip-audit

# 2. Mise à jour de la contrainte dans requirements.in
cat << 'EOF' > app/requirements.in
fastapi>=0.109.1
uvicorn[standard]
argon2-cffi
starlette>=0.40.0
pydantic
requests>=2.32.4
pyyaml
jinja2
urllib3>=2.8.0
idna>=3.7
slowapi
EOF

# 3. Régénération du lockfile avec les empreintes sha256
pip-compile --generate-hashes app/requirements.in -o app/requirements.txt

# 4. Installation et vérification de la propreté du venv
pip install -r app/requirements.txt
pip-audit -r app/requirements.txt

# 5. Validation de la suite de tests
pytest

# 6. Rebuild et vérification du conteneur Docker durci (exécution en appuser)
docker build -t minishop-secure -f app/Dockerfile .
docker run --rm minishop-secure whoami
```

## 5. Rotation des secrets

Le package compromis ayant pu s'exécuter avec les privilèges du processus Python, la variable `SECRET_KEY` présente en mémoire a potentiellement été exfiltrée. Nous avons donc renouvelé l'ensemble des secrets.

### Commandes de rotation

```
# 1. Génération d'une nouvelle clé secrète aléatoire de 64 caractères
openssl rand -hex 32

# 2. Mise à jour du fichier .env local
sed -i 's/^SECRET_KEY=.*/SECRET_KEY='$(openssl rand -hex 32)'/' .env

# 3. Mise à jour du secret GitHub Actions pour la CI/CD
gh secret set SECRET_KEY -b"$(openssl rand -hex 32)"
```

_Note : Le changement de `SECRET_KEY` invalide automatiquement tous les cookies de session existants côté utilisateur._

## 6. Retour d'expérience (REX)

### Ce qui a bien fonctionné

- La CI/CD (`pip-audit` + `trivy`) et Dependabot ont détecté le problème immédiatement avant le déploiement en production.
    
- Le conteneur Docker tournant avec un utilisateur non-privilégié (`USER appuser`), l'impact potentiel sur l'hôte était fortement limité.
    
- L'épinglage par hashes (`--hash=sha256:`) empêche l'installation accidentelle de paquets altérés au build.
    

### Axes d'amélioration

- Mettre en place un proxy de dépendances interne (ex: Nexus, Artifactory ou PyPI mirror) avec validation automatique préalable.
    
- Ajouter des règles de filtrage réseau sortant (Egress filtering) sur le conteneur Docker pour bloquer les appels réseau vers des hôtes non autorisés.