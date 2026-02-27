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

FormShield::enforce('contact', $_POST, false);

// Qui tua logica reale...
echo "OK (form superato)";
