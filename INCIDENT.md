# Rapport d'incident : version compromise de `requests`

> Scénario fictif : on suppose que `requests==2.34.2` (version verrouillée dans `requirements.txt`) est annoncée compromise le 29/10/2026. La version saine `2.34.3` est hypothétique. Les noms `deploy.yml` et `minishop-app` sont des exemples : le dépôt ne contient que `security.yml`.

**Date :** 29 octobre 2026 · **Sévérité :** Critique

## Chronologie (fictive)
| Heure | Événement |
|-------|-----------|
| 09:00 | Un avis public annonce que `requests==2.34.2` est compromise. |
| 09:15 | Détection : `pip-audit` et Trivy signalent la version dans le lockfile. |
| 09:30 | Évaluation d'exposition : la version est bien installée (lockfile, image, CI). |
| 10:00 | Confinement : coupure réseau du conteneur, copie des preuves, déploiements bloqués. |
| 11:00 | Correction : version exclue, lockfile régénéré, image reconstruite et analysée. |
| 12:00 | Rotation de `SECRET_KEY` et des autres secrets, redéploiement. |
| J+1 | Surveillance, puis retour d'expérience. |

## Impact
- **Secrets :** la bibliothèque s'exécute dans le processus de l'application. Elle a donc accès à `SECRET_KEY` (variable d'environnement). Avec cette clé, un attaquant peut forger des cookies de session.
- **Trafic sortant :** `requests` effectue les appels HTTP de `/fetch`. Elle voit les URL demandées et les réponses, et du code malveillant pourrait contacter n'importe quel hôte (la liste blanche protège l'application, pas la bibliothèque elle-même).
- **Données :** la base SQLite contient des comptes utilisateurs (mots de passe hachés en Argon2) et des factures. Elle est lisible par le processus compromis.
- **CI :** les builds exécutés après l'adoption de la version ont pu l'installer et exposer les secrets du workflow.

## Communication
- **En interne :** équipe de développement et responsable sécurité prévenus dès la détection, point d'avancement à chaque étape.
- **Clients / utilisateurs :** information si l'analyse montre que des données ont pu être consultées, avec invitation à changer leur mot de passe.
- **CNIL :** si des données personnelles sont concernées, notification d'une violation de données sous 72 h (art. 33 du RGPD).

## 1. Détection
Un avis annonce que `requests==2.34.2` est compromise.

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
git log -S"requests==2.34.2" --oneline -- app/requirements.txt

# Version réellement présente dans l'image et dans le venv
docker run --rm minishop pip freeze | grep -i requests
pip show requests

# Qui dépend de requests, et où le code l'utilise
pip install pipdeptree
pipdeptree -r -p requests
grep -rn "requests" app/app.py

# Quels builds CI ont pu installer la version compromise
gh run list --created ">=2026-10-29" --json databaseId,conclusion,headSha
```
Il faut aussi consulter les logs réseau sortants pour repérer des connexions inhabituelles. Si la version compromise n'a jamais été installée (lockfile antérieur), l'exposition est nulle.

## 3. Confinement
On isole et on conserve les preuves avant de supprimer quoi que ce soit.

```bash
docker network disconnect bridge minishop-app        # coupe les communications sortantes
docker logs minishop-app > app.log                   # logs applicatifs
docker commit minishop-app evidence:requests-incident
docker save evidence:requests-incident -o evidence.tar
docker stop minishop-app

gh workflow disable deploy.yml                       # bloque les déploiements (nom d'exemple)
# + protection de branche sur main (revue obligatoire)
```
Les environnements compromis (`.venv`, image) sont supprimés seulement après la copie des preuves.

## 4. Correction
```bash
# Exclure la version compromise (ou épingler une version saine connue)
echo "requests!=2.34.2" >> app/requirements.in   # ou requests==2.34.3

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
printf %s "$NEW" | gh secret set SECRET_KEY          # si le secret existe côté GitHub
```
Les sessions existantes sont invalidées. Autres secrets à renouveler le cas échéant : tokens GitHub, clés cloud (désactiver, créer, supprimer), identifiants du registre Docker. Les mots de passe des comptes de démonstration créés par `init_db()` doivent aussi être changés (ils sont fixes dans le code). Vérification : `gitleaks detect`.

## 6. Retour d'expérience
**Bien fonctionné :** pip-audit, Trivy et Dependabot dans la CI ; conteneur non-root, avec un code en lecture seule pour `appuser` (fichiers appartenant à root) ; SBOM pour retrouver rapidement les dépendances.

**Limites :** les hashes garantissent l'intégrité du fichier **par rapport au lockfile**. Si la version compromise y est déjà, pip l'installe fidèlement. Ils protègent contre une altération après le verrouillage, pas contre une compromission à la source.

**Améliorations :** délai de carence avant d'adopter une nouvelle version (`cooldown` Dependabot) ; filtrage du trafic sortant du conteneur ; miroir PyPI interne ; procédure d'astreinte et exercice annuel.
