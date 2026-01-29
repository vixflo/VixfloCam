# Analiză - Testare pe dispozitive (Windows/macOS)

## Obiectiv

- Validare pe mai multe PC-uri:
  - instalare curată
  - rulare stream RTSP
  - PTZ + Events + Recording + Notifications

## Checklist minim

- Camera list load/save (`data/cameras.json`)
- Playback + reconnect
- PTZ connect + move + stop
- Event Recording: motion/person (cu setările corecte)
- Events list + play clip
- Notificări desktop

## TODO

- Matrice de test (OS/versiuni VLC/camere/firmware).
- Script de „smoke test” manual + log collection.
