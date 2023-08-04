<?php

namespace CodeEncrypter\Laravel\Commands;

use Exception;
use Illuminate\Console\Command;
use Illuminate\Encryption\Encrypter;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use SplFileInfo;

class CodeDecryptCommand extends Command
{
    protected $signature = 'code:decrypt {key} {--cipher=}';

    protected $files;

    public function __construct(Filesystem $files)
    {
        parent::__construct();

        $this->files = $files;
    }

    public function handle()
    {
        $cipher = $this->option('cipher') ?: config('code-encrypter.cipher');

        $key = $this->argument('key');

        $paths = Arr::wrap(config('code-encrypter.paths'));

        $collection = collect();

        foreach ($paths as $path) {
            $recursive = Str::endsWith($path, '/**');

            $path = Str::of($path)->rtrim('/*');

            if (! $this->files->exists($path)) {
                continue;
            }

            $subset = collect();

            if ($this->files->isFile($path)) {
                $file = new SplFileInfo($path);

                $subset->push($file->getRealPath());
            } elseif ($this->files->isDirectory($path)) {
                $method = $recursive ? 'allFiles' : 'files';

                $files = $this->files->{$method}($path);

                foreach ($files as $file) {
                    $subset->push($file->getRealPath());
                }
            }

            $subset->each(function ($file) use ($collection) {
                if ($this->isEncryptedFile($file)) {
                    $collection->push($file);
                }
            });
        }

        if ($collection->isEmpty()) {
            $this->newLine();
            $this->components->error('No PHP files to decrypt.');

            return Command::FAILURE;
        }

        try {
            $encrypter = new Encrypter($this->parseKey($key), $cipher);

            $collection->each(function ($file) use ($encrypter) {
                $payload = $encrypter->decryptString(Str::of($this->files->get($file))->after('// base64:'));

                $result = $this->files->put($file, '<?php'.$payload);

                $this->components->twoColumnDetail($result ? sprintf('<fg=red>%s</fg=red>', 'Decrypted') : 'Not Decrypted', $file);
            });
        } catch (Exception $e) {
            $this->newLine();
            $this->components->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->newLine();
        $this->components->info('Command successfully completed.');

        return Command::SUCCESS;
    }

    protected function parseKey($key)
    {
        if (Str::startsWith($key, $prefix = 'base64:')) {
            $key = base64_decode(Str::after($key, $prefix));
        }

        return $key;
    }

    protected function isEncryptedFile($file)
    {
        if ($this->files->extension($file) != 'php') {
            return false;
        }

        $contents = Str::of($this->files->get($file))->trim();

        return Str::startsWith($contents, '<?php \Zephir');
    }
}
