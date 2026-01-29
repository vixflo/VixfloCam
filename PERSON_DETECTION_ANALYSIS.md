# Analiză - Detectarea Persoanelor (ONVIF Events)

## Obiectiv

- Detectare „person/human/people” pe camerele care emit evenimente ONVIF.
- Pornit/oprit + personalizare (durată înregistrare, cooldown, notificări).
- La trigger, înregistrare automată ~50–60s și creare eveniment pentru notificări.

## Implementare curentă (în proiect)

- Sursa semnalelor: ONVIF Events PullPoint (best-effort) în `vixflocam/onvif_events.py`.
- Buclă de polling + filtrare semnale: `vixflocam/app.py` (`_on_event_recording_toggled`).
- Setări: `vixflocam/settings.py` (`detect_person`, `event_record_seconds`, `event_cooldown_seconds`, `desktop_notifications`).
- Persistare evenimente: `vixflocam/events_store.py` → `data/events.json`.

## Logică de detecție

- Semnalele sunt tratate ca listă de string-uri (Topics + SimpleItem Name=Value).
- „Person” este detectat dacă apare `person/people/human` în topic-uri sau item-uri.

## Configurare (UI)

- Buton „Event Settings” în UI:
  - Detect person: on/off
  - Record duration: 10–300s (default 60s)
  - Cooldown: 5–300s (default 20s)
  - Desktop notifications: on/off

## TODO (îmbunătățiri)

- Mapare mai strictă pe standardele ONVIF Topics (camera-specific).
- Nivel de „sensibility”/filtre per cameră (nu global).
- „Prebuffer”: păstrează ultimele N secunde înainte de trigger (din rolling clips) și le concatenează cu post-trigger.
