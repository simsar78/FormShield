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

FormShield::enforce('api_save', $_POST, true);

header('Content-Type: application/json; charset=utf-8');
echo json_encode([
  'ok' => true,
  'saved' => true,
  'data' => [
    'name' => $_POST['name'] ?? null,
  ],
]);
