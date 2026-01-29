# Analiză - Evenimente (log + bază pentru notificări)

## Obiectiv

- Orice trigger (motion/person) generează un „eveniment” structurat.
- Evenimentele se folosesc pentru:
  - listare în UI (panoul Events)
  - notificări desktop
  - integrare viitoare (email/telegram/webhook)

## Implementare curentă

- Persistare: `vixflocam/events_store.py` → `data/events.json` (max ~500 evenimente).
- Listare: `vixflocam/app.py` (`_refresh_events_list`) afișează evenimentele, cu fallback pe fișiere `.ts`.

## Structura unui eveniment

- `ts` (epoch seconds)
- `camera_id`, `camera_name`
- `kind` (`motion` / `person` / `unknown`)
- `topics` (lista brută de string-uri primite)
- `file` (cale către clipul înregistrat)

## TODO

- Paginare + filtre în UI (camera, tip, interval).
- „Clear events” + export (CSV/JSON).
- Asociere eveniment ↔ clip prebuffer/postbuffer (dacă implementăm concatenarea).
