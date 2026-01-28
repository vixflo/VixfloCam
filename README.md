# VixfloCam (Windows)

Viewer simplu pentru camere IP (ex: TP-Link Tapo) prin RTSP, construit cu **Python + PySide6 + LibVLC**.

## Cerințe

- Windows 10/11
- Python (deja ai)
- **VLC Media Player (64-bit)** instalat (necesar pentru librăriile `libvlc`).
  - Download: https://www.videolan.org/vlc/

## Instalare (dependințe)

În acest workspace există deja un virtualenv în `.venv`. Dacă ai clonat proiectul în altă parte și nu există `.venv`, îl poți crea așa:

```powershell
python -m venv .venv
```

Apoi instalezi pachetele:

```powershell
./.venv/Scripts/python.exe -m pip install -r requirements.txt
```

## Pornire rapidă

1. Instalează VLC (dacă nu e instalat)
2. Deschide un terminal PowerShell în folderul proiectului (acesta)
3. Rulează aplicația:

```powershell
C:/xampp/htdocs/vixflodev-ro/VixfloCam/.venv/Scripts/python.exe -m vixflocam
```

sau direct

```
.venv/Scripts/python.exe -m vixflocam
```

Dacă nu vrei calea lungă, merge și:

```powershell
./.venv/Scripts/python.exe -m vixflocam
```

## Adăugare cameră

În aplicație, apasă **Add** și introdu:
- **Name** (un nume pentru cameră)
- **Host / IP** (ex: `192.168.1.50`)
- **Username** (dacă ai setat user în Tapo; altfel poate fi gol)
- **Password** (parola camerei / contului local)
- **Port** (de obicei `554`)
- **Stream path** (de obicei `stream1` sau `stream2`)
- **ONVIF port (0=off)** (dacă vrei PTZ Pan/Tilt).
  - Pentru Tapo, conform FAQ Tapo, ONVIF este pe **portul 2020**, iar RTSP pe **portul 554**.

În formular apare și un câmp **RTSP Preview** care îți arată URL-ul generat, de forma:

```text
rtsp://USER:PASS@192.168.1.50:554/stream1
```

Notă: dacă parola conține caractere speciale (ex: `@`), aplicația va face automat URL-encoding în preview (ex: `@` → `%40`).

Notă: pentru Tapo, RTSP trebuie activat din aplicația Tapo (în funcție de firmware/model). Dacă nu merge, poți folosi și un URL custom (aplicația nu impune un format).

## Config

Camerele se salvează local în:
- `./data/cameras.json`

Parolele sunt salvate criptat cu Windows DPAPI (legate de user-ul tău Windows).

## Funcții

- Audio + control volum (slider + mute)
- PTZ (Pan/Tilt) prin ONVIF (dacă activezi ONVIF și setezi portul)
  - În **Edit Camera** ai buton **Detect ONVIF port** (încearcă automat porturile comune)
  - Notă: nu toate camerele au PTZ. Dacă ONVIF nu raportează serviciul PTZ, vei vedea „PTZ: not supported by camera”.
- Înregistrare locală (Start/Stop Recording)
  - Fișierele se salvează în: `./data/recordings/` (format `.ts`)

## Înregistrare fără UI (background)

Dacă vrei ca toate camerele să înregistreze **și când aplicația UI nu este pornită**, poți rula recorder-ul headless:

```powershell
./.venv/Scripts/python.exe -m vixflocam.recorder
```

Acest mod face "rolling recording" pe segmente `.ts` pentru toate camerele configurate (din `data/cameras.json`) și poate fi pus în Task Scheduler (Run at startup / Run whether user is logged on or not).
