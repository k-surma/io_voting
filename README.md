# Minimalna strona Flask + Gmail SMTP (port 3000)

Prosta strona z formularzem kontaktowym. Wysyła maile przez Gmail SMTP (App Password). Uruchomienie na VPS bez reverse proxy (port 3000).

## Wymagania
- Python 3.10+
- Dostęp do konta Gmail z 2FA + App Password

## Konfiguracja
1. Sklonuj/kopiuj projekt na VPS
2. Stwórz i aktywuj wirtualne środowisko
```bash
python3 -m venv .venv
source .venv/bin/activate
```
3. Zainstaluj zależności
```bash
pip install -r requirements.txt
```
4. Skopiuj plik środowiska i uzupełnij dane
```bash
cp env.example .env
nano .env
```
5. Uruchom aplikację na porcie 3000
```bash
python app.py
```
Aplikacja nasłuchuje na `0.0.0.0:3000`.

## Utrzymanie (tymczasowo, bez reverse proxy)
- Uruchom w tle (prosto):
```bash
nohup python app.py > app.log 2>&1 &
```
- Zatrzymanie procesu:
```bash
pkill -f "python app.py"
```

## Uwaga dot. Gmail SMTP
- Włącz 2FA na koncie, wygeneruj App Password i użyj go jako `SMTP_PASSWORD`.
- Pola konfiguracyjne: `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, TLS (STARTTLS).

## Test zdrowia
- Endpoint: `/healthz` powinien zwrócić `ok`.

## Lokalnie (Windows PowerShell)
```powershell
python -m venv .venv
. .venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy env.example .env
notepad .env
$env:PORT=3000
python app.py
```
