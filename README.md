# FormShield (PHP puro) — CSRF + Honeypot + Time-gate + Rate limiter

Libreria **100% custom** (senza servizi esterni) per proteggere **form POST** e **AJAX POST** da bot/spam.
Compatibile con **PHP 7.x e 8.x** (richiede PHP >= 7.2).

## Installazione (da repo locale / zip)
1. Metti questa libreria in una cartella, es: `packages/formshield`
2. Nel tuo progetto, aggiungi in `composer.json`:

```json
{
  "repositories": [
    { "type": "path", "url": "packages/formshield" }
  ],
  "require": {
    "simsar78/formshield": "*"
  }
}
```

Poi esegui:
```bash
composer update
```

> In alternativa, puoi pubblicarla su un tuo Git (GitHub/Gitea) e installarla via VCS.

## Quick start

### 1) Bootstrap
Nel tuo bootstrap (prima di usare la libreria):
```php
use FormShield\FormShield;

FormShield::init([
  'default' => [
    'timegate_min' => 3,
    'ratelimit' => ['max' => 10, 'window' => 600],
  ],
  'actions' => [
    'contact' => [
      'ratelimit' => ['max' => 5, 'window' => 600],
    ],
    'api_save' => [
      'timegate_min' => 0, // AJAX on-load: non bloccare
      'ratelimit' => ['max' => 60, 'window' => 60],
    ],
  ],
]);
```

### 2) Form POST classico
Nella pagina del form:
```php
<?= FormShield::render('contact') ?>
```

Nel submit:
```php
FormShield::enforce('contact', $_POST, false);
```

### 3) AJAX POST
Nella pagina (esponi payload JS):
```php
<script>
window.FS = <?= json_encode(FormShield::clientPayload('api_save')) ?>;
</script>
```

Nel client, invia i campi `_fs_id`, `_fs_ts`, `_fs_csrf` oltre ai tuoi dati:
```js
fetch('/api/save.php', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: new URLSearchParams({
    _fs_id: window.FS.form_id,
    _fs_ts: window.FS.ts,
    _fs_csrf: window.FS.csrf,
    // ... i tuoi campi
  })
})
.then(r => r.json())
.then(console.log);
```

Nel server:
```php
FormShield::enforce('api_save', $_POST, true);
```

## Note UX
- Se fallisce, per AJAX torna JSON con `{ok:false, code, message}`.
- Per form classico, di default stampa un messaggio. Nel tuo progetto conviene fare **redirect + flash**.
- Il **time-gate** è server-side; JS per disabilitare il bottone è solo un miglioramento UX.

## Sicurezza
- Messaggi volutamente generici (in modalità `generic`) per non “insegnare” ai bot.
- Puoi loggare il `reason` in `fail()` se ti serve audit.

## Licenza
MIT
