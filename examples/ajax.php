<?php
require __DIR__ . '/../vendor/autoload.php';

use FormShield\FormShield;

FormShield::init([
  'actions' => [
    'api_save' => [
      'timegate_min' => 0,
      'ratelimit' => ['max' => 60, 'window' => 60],
    ],
  ],
]);

$payload = FormShield::clientPayload('api_save');
?><!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <title>Example AJAX</title>
</head>
<body>
  <h1>AJAX POST</h1>
  <button id="btn">Invia richiesta</button>

  <script>
  window.FS = <?= json_encode($payload) ?>;

  document.getElementById('btn').addEventListener('click', async () => {
    const body = new URLSearchParams({
      _fs_id: window.FS.form_id,
      _fs_ts: window.FS.ts,
      _fs_csrf: window.FS.csrf,
      name: 'Simone'
    });

    const res = await fetch('api_save.php', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body
    });

    const data = await res.json();
    console.log(data);
    alert(JSON.stringify(data));
  });
  </script>
</body>
</html>
