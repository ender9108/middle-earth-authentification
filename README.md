# psr15-authentification

[![Build Status](https://travis-ci.org/ender9108/middle-earth-authentification.svg?branch=master)](https://travis-ci.org/ender9108/middle-earth-authentification)
[![Coverage Status](https://coveralls.io/repos/github/ender9108/middle-earth-authentification/badge.svg?branch=master)](https://coveralls.io/github/ender9108/middle-earth-authentification?branch=master)

## Auth Basic
```php
<?php
$basic = new BasicAuthentication([
    'mylogin1' => 'mypassword1',
    'mylogin2' => 'mypassword2'
]);

// Example with enderlab/psr15-middle-earth-framework
$app = \EnderLab\Application\AppFactory::create();
$app->pipe($basic);
$app->run();
```

## Auth digest
```php
<?php
$digest = new DigestAuthentication(
    [
        'mylogin1' => 'mypassword1',
        'mylogin2' => 'mypassword2'
    ],
    uniqid(), // $nonce
    'my digest auth' // $realm
);

// Example with enderlab/psr15-middle-earth-framework
$app = \EnderLab\Application\AppFactory::create();
$app->pipe($digest);
$app->run();
```

## Auth JWT
```php
<?php
$jwt = new JwtAuthentication([
    'privateKey' => 'My secure private key of death',
    'algorithm' => 'HS512'
]);

// Example with enderlab/psr15-middle-earth-framework
$app = \EnderLab\Application\AppFactory::create();
$app->pipe($jwt);
$app->run();
```