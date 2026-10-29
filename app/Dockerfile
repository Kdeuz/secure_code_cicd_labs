FROM python:3.11-slim

WORKDIR /app

# Création d'un utilisateur non-root
RUN useradd -m -u 1000 appuser

COPY app/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

RUN chown -R appuser:appuser /app

# Définition de l'utilisateur non-root
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]