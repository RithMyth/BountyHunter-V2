# BountyHunter V2.0 🎯

BountyHunter ist ein spezialisiertes Python-Tool für Sicherheitsanalysen und Penetration Testing. Es wurde entwickelt, um Webanwendungen auf versteckte Geheimnisse in JavaScript-Dateien, Fehlkonfigurationen und potenzielle Login-Schwachstellen zu prüfen.

## Features
- **Deep JS Analysis**: Extrahiert Arrays und Variablen aus JavaScript-Dateien (z.B. Emails, Dictionaries).
- **Entropy Check**: Findet hochgradig zufällige Strings, die auf API-Keys oder Token hinweisen.
- **Auto-PWN**: Testet extrahierte Credentials automatisch gegen gefundene Login-Formulare.
- **Log Analysis**: Analysiert `auth.log` auf Brute-Force-Aktivitäten.
- **Full Report**: Generiert einen interaktiven HTML-Report mit allen Funden.

## Installation
1. Repository klonen:
2. python3 BountyHunter.py   (Url einsetzen)
   
```bash
   git clone https://github.com/RithMyth/BountyHunter-V2.git
