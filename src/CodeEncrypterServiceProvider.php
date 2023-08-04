<?php

namespace CodeEncrypter\Laravel;

use CodeEncrypter\Laravel\Commands\CodeDecryptCommand;
use CodeEncrypter\Laravel\Commands\CodeEncryptCommand;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class CodeEncrypterServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('code-encrypter')
            ->hasConfigFile()
            ->hasCommands([
                CodeEncryptCommand::class,
                CodeDecryptCommand::class,
            ]);
    }
}
