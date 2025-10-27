# Minimalna strona Flask + Gmail SMTP (port 3000)

Prosta strona do konkursów z głosowaniem e‑mailowym i panelem admina.

## Wymagania
- Python 3.10+
- Gmail konto z 2FA + App Password

## Konfiguracja
1. Wirtualne środowisko
```bash
python3 -m venv .venv
source .venv/bin/activate
```
2. Zależności
```bash
pip install -r requirements.txt
```
3. Konfiguracja środowiska
```bash
cp env.example .env
nano .env
```
Minimalne pola do wypełnienia:
- `FLASK_SECRET_KEY` – dowolny losowy sekret
- `SMTP_USERNAME` – Twój email Gmail
- `SMTP_PASSWORD` – App Password (z 2FA)
- `MAIL_FROM`, `MAIL_TO_DEFAULT` – zwykle ten sam email
- `ADMIN_USERNAME`, `ADMIN_PASSWORD` – pierwszy admin (zostanie utworzony automatycznie)

4. Start aplikacji
```bash
python app.py
```
Aplikacja nasłuchuje na `0.0.0.0:3000`.

## Admin
- Logowanie: `/admin/login`
- Panel: `/admin`
- Tworzenie konkursu: przycisk „Utwórz konkurs”
- Dodawanie projektów: na stronie szczegółów konkursu

## Publicznie
- Strona główna: lista konkursów i projektów
- Strona konkursu: wybór projektu + podanie e‑maila → przychodzi kod
- Weryfikacja: `/contest/<id>/verify` – wpisz kod z e‑maila

## Utrzymanie (na szybko, bez reverse proxy)
```bash
nohup python app.py > app.log 2>&1 &
```
Zatrzymanie:
```bash
pkill -f "python app.py"
```

## Uwaga dot. Gmail SMTP
- `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, STARTTLS
- Kod ważny 15 minut, jeden głos na e‑mail w konkursie

## Windows PowerShell (lokalnie)
```powershell
python -m venv .venv
. .venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy env.example .env
notepad .env
python app.py
```
