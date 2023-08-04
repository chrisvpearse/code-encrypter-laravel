<?php

return [
    'paths' => [
        app_path('Http/Controllers/Foo/*'),
        app_path('Http/Controllers/Bar/**'),
        app_path('Http/Controllers/HelloWorld.php'),
    ],
    'cipher' => config('app.cipher') ?: 'AES-256-CBC',
    'minify' => false,
];
