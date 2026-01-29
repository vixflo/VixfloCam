# Analiză - Build Executabil (Windows/macOS)

## Obiectiv

- Executabil desktop:
  - Windows: `.exe` (MSI/installer opțional)
  - macOS: `.app` (dacă proiectul va suporta macOS)

## Observații tehnice

- Dependențe: PySide6, python-vlc, VLC instalat (sau bundle libvlc).
- Pentru Windows: PyInstaller este ruta cea mai simplă.

## TODO

- Script de build (PyInstaller spec) + includere icon.
- Detectare/bundle libvlc (opțional) sau ghid instalare VLC.
- Pipeline de release (versioning + changelog).
