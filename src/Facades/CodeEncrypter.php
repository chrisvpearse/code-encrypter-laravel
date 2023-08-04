<?php

namespace CodeEncrypter\Laravel\Facades;

use Illuminate\Support\Facades\Facade;

class CodeEncrypter extends Facade
{
    protected static function getFacadeAccessor()
    {
        return \CodeEncrypter\Laravel\CodeEncrypter::class;
    }
}
