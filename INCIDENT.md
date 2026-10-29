# Rapport d'incident : version compromise de `requests`

**Date :** 29 octobre 2026 · **Sévérité :** Critique

## 1. Détection
Un avis annonce que `requests==X.Y.Z` est compromise.

```bash
pip-audit -r app/requirements.txt
trivy fs app/
gh run list --workflow=security.yml --limit 10
```

## 2. Évaluation d'exposition
Objectif : savoir si la version compromise a été installée, où, et quand.

```bash
# Version verrouillée, et depuis quel commit
grep -n "^requests==" app/requirements.txt
git log -S"requests==X.Y.Z" --oneline -- app/requirements.txt

# Version réellement présente dans l'image et dans le venv
docker run --rm minishop pip freeze | grep -i requests
pip show requests

# Qui dépend de requests, et où le code l'utilise
pipdeptree -r -p requests
grep -rn "requests" app/app.py

# Quels builds CI ont pu installer la version compromise
gh run list --created ">=YYYY-MM-DD" --json databaseId,conclusion,headSha
```
Il faut aussi consulter les logs réseau sortants pour repérer des connexions inhabituelles. Si la version compromise n'a jamais été installée (lockfile antérieur), l'exposition est nulle.

## 3. Confinement
On isole et on conserve les preuves avant de supprimer quoi que ce soit.

```bash
docker network disconnect bridge minishop-app        # coupe les communications sortantes
docker commit minishop-app evidence:requests-incident
docker save evidence:requests-incident -o evidence.tar
docker stop minishop-app

gh workflow disable deploy.yml                       # bloque les déploiements
# + protection de branche sur main (revue obligatoire)
```
Les environnements compromis (`.venv`, image) sont supprimés seulement après la copie des preuves.

## 4. Correction
```bash
# Exclure la version compromise (ou épingler une version saine connue)
echo "requests!=X.Y.Z" >> app/requirements.in   # ou requests==A.B.C

pip-compile --generate-hashes app/requirements.in -o app/requirements.txt
python -m venv /tmp/clean && /tmp/clean/bin/pip install --require-hashes -r app/requirements.txt
pip-audit -r app/requirements.txt
pytest -q tests

docker build --no-cache -t minishop:fixed -f app/Dockerfile .
trivy image minishop:fixed
```

## 5. Rotation des secrets
La version compromise s'exécutait dans le processus de l'application : on suppose que tout ce qui est en environnement ou en mémoire a fuité.

```bash
NEW=$(openssl rand -hex 32)                          # une seule génération
sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$NEW/" .env
gh secret set SECRET_KEY --body "$NEW"
```
Les sessions existantes sont invalidées. Autres secrets à renouveler : clés AWS (désactiver, créer, supprimer), tokens GitHub, identifiants du registre Docker, mots de passe de la base. Vérification : `gitleaks detect`.

## 6. Retour d'expérience
**Bien fonctionné :** pip-audit, Trivy et Dependabot dans la CI ; conteneur non-root avec code en lecture seule ; SBOM pour retrouver rapidement les dépendances.

**Limites :** les hashes garantissent l'intégrité du fichier **par rapport au lockfile**. Si la version compromise y est déjà, pip l'installe fidèlement. Ils protègent contre une altération après le verrouillage, pas contre une compromission à la source.

**Améliorations :** délai de carence avant d'adopter une nouvelle version (`cooldown` Dependabot) ; filtrage du trafic sortant du conteneur ; miroir PyPI interne ; procédure d'astreinte et exercice annuel.
