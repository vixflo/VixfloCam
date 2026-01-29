# Analiză - Detectarea Mișcării (ONVIF Events)

## Obiectiv

- Detectare „motion” pe camerele care emit evenimente ONVIF (Topics/SimpleItems).
- Pornit/oprit + personalizare (durată înregistrare, cooldown, notificări).

## Implementare curentă (în proiect)

- Sursa semnalelor: ONVIF Events PullPoint în `vixflocam/onvif_events.py`.
- Filtrare semnale în `vixflocam/app.py` (caută `motion`, `cellmotiondetector`, etc).
- Setări: `vixflocam/settings.py` (`detect_motion`, `event_record_seconds`, `event_cooldown_seconds`).

## Notă despre compatibilitate

- Multe camere encodează motion ca `SimpleItem(Name=IsMotion, Value=true)` sau topic-uri proprietare.
- Implementarea e „best-effort”, deci trebuie validată per model/firmware.

## TODO (îmbunătățiri)

- Config per cameră (liste de cuvinte-cheie/regex).
- Afișare în UI a ultimelor topic-uri primite pentru calibrare.
