<?php
require __DIR__ . '/../vendor/autoload.php';

use FormShield\FormShield;

FormShield::init([
  'actions' => [
    'contact' => [
      'timegate_min' => 3,
      'ratelimit' => ['max' => 5, 'window' => 600],
    ],
  ],
]);

?><!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <title>Example form</title>
</head>
<body>
  <h1>Contatti</h1>
  <form method="post" action="submit.php">
    <?= FormShield::render('contact') ?>
    <p><input type="email" name="email" placeholder="Email" required></p>
    <p><textarea name="message" placeholder="Messaggio" required></textarea></p>
    <button type="submit">Invia</button>
  </form>
</body>
</html>
