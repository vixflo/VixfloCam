# Analiză - Notificări Desktop (Windows)

## Obiectiv

- La eveniment (motion/person), afișare notificare pe desktop.
- Setare on/off din UI.

## Implementare curentă

- Qt `QSystemTrayIcon.showMessage` în `vixflocam/app.py` (`_notify_event`).
- Activare/dezactivare din `Event Settings` (`desktop_notifications`).

## TODO

- Notificări mai bogate (icon, acțiuni: „Open events”, „Play clip”).
- Log notificări + throttling (să nu spam-uiască).
