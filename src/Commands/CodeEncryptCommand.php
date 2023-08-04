<?php

namespace CodeEncrypter\Laravel\Commands;

use Exception;
use Illuminate\Console\Command;
use Illuminate\Encryption\Encrypter;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use SplFileInfo;

class CodeEncryptCommand extends Command
{
    protected $signature = 'code:encrypt {--key=} {--cipher=}';

    protected $files;

    public function __construct(Filesystem $files)
    {
        parent::__construct();

        $this->files = $files;
    }

    public function handle()
    {
        $cipher = $this->option('cipher') ?: config('code-encrypter.cipher');

        $key = $this->option('key') ?: Encrypter::generateKey($cipher);

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
                $this->isValidPhpFile($file) ? $collection->push($file) : $this->components->twoColumnDetail('Invalid PHP File', $file);
            });
        }

        if ($collection->isEmpty()) {
            $this->newLine();
            $this->components->error('No PHP files to encrypt.');

            return Command::FAILURE;
        }

        try {
            $zephirCode = $this->generateZephirClassCode($this->parseKey($key), $cipher, config('code-encrypter.minify'));

            if (! $this->files->exists($tmpDirectory = base_path('tmp/code-encrypter'))) {
                $this->files->makeDirectory($tmpDirectory, 0755, true);
            }

            $this->files->cleanDirectory($tmpDirectory);
            $this->files->makeDirectory($zephirDirectory = $tmpDirectory.'/zephir/zephir', 0755, true);

            if (! $this->files->put($zephirFile = $zephirDirectory.'/encrypter.zep', $zephirCode)) {
                throw new Exception('Could not create a file containing the Zephir code.');
            }

            $zephirFile = new SplFileInfo($zephirFile);

            $encrypter = new Encrypter($this->parseKey($key), $cipher);

            $collection->each(function ($file) use ($encrypter) {
                $payload = $encrypter->encryptString(Str::of($this->files->get($file))->after('<?php'));

                $decoded = json_decode(base64_decode($payload), true);

                $result = $this->files->put($file, $this->generatePhpCode($payload, $decoded['value'], $decoded['iv']).PHP_EOL);

                $this->components->twoColumnDetail($result ? sprintf('<fg=green>%s</fg=green>', 'Encrypted') : 'Not Encrypted', $file);
            });
        } catch (Exception $e) {
            $this->newLine();
            $this->components->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->newLine();
        $this->components->info('Command successfully completed.');

        $this->components->twoColumnDetail('Key', 'base64:'.base64_encode($this->parseKey($key)));
        $this->components->twoColumnDetail('Cipher', $cipher);
        $this->components->twoColumnDetail('Zephir File', $zephirFile->getRealPath());
        $this->components->twoColumnDetail(sprintf('%s <fg=red>%s</fg=red>', 'Zephir Temp Directory', '(Must Delete)'), $tmpDirectory);

        return Command::SUCCESS;
    }

    protected function parseKey($key)
    {
        if (Str::startsWith($key, $prefix = 'base64:')) {
            $key = base64_decode(Str::after($key, $prefix));
        }

        return $key;
    }

    protected function isValidPhpFile($file)
    {
        if ($this->files->extension($file) != 'php') {
            return false;
        }

        $contents = Str::of($this->files->get($file))->trim();

        return Str::startsWith($contents, '<?php') &&
            ! Str::startsWith($contents, '<?php \Zephir') &&
            ! Str::endsWith($contents, '?>');
    }

    protected function generatePhpCode($payload, $data, $iv)
    {
        return <<<PHP
        <?php \Zephir\Encrypter::decrypt("{$data}", "{$iv}");
        // base64:{$payload}
        PHP;
    }

    protected function generateZephirClassCode($key, $cipher, $minify = true)
    {
        $callback = $this->generateSafeName();
        $data = $this->generateSafeName();
        $iv = $this->generateSafeName();

        $zep = <<<ZEP
        namespace Zephir;

        class Encrypter
        {
            public static function decrypt(var {$data}, var {$iv})
            {
                return eval(self::{$callback}({$data}, {$iv}));
            }
            // @methods
        }
        ZEP;

        $methods = [
            $this->generateZephirMethodCode($key, $cipher, $callback, $data, $iv),
        ];

        for ($i = 1; $i <= random_int(4, 8); $i++) {
            $methods[] = $this->generateZephirMethodCode(
                Encrypter::generateKey($cipher),
                $cipher,
                $this->generateSafeName(),
                $this->generateSafeName(),
                $this->generateSafeName()
            );
        }

        shuffle($methods);

        $zep = Str::replace('// @methods', implode(PHP_EOL, $methods), $zep);

        if (! $minify) {
            return $zep;
        }

        $lines = explode(PHP_EOL, $zep);

        foreach ($lines as &$line) {
            $line = str_pad($line, random_int(1, 16), ' ', STR_PAD_LEFT);
            $line = str_pad($line, random_int(1, 16), ' ', STR_PAD_RIGHT);
        }

        return implode($lines);
    }

    protected function generateSafeName()
    {
        return Str::password(random_int(4, 8), true, false, false).Str::password(random_int(8, 12), true, true, false);
    }

    protected function generateZephirMethodCode($key, $cipher, $callback, $data, $iv)
    {
        $a = $this->generateSafeName();
        $arr = $this->generateZephirArray(bin2hex($key));

        return PHP_EOL.<<<ZEP
            protected static function {$callback}(var {$data}, var {$iv})
            {
                var {$a};

                let {$a} = {$arr};

                return openssl_decrypt(
                    {$data},
                    "{$cipher}",
                    hex2bin(implode({$a})),
                    0,
                    base64_decode({$iv})
                );
            }
        ZEP;
    }

    protected function generateZephirArray($key)
    {
        $string = '';

        for ($i = 0; $i < Str::length($key); $i += 2) {
            $string = Str::of($string)->append('"')->append(Str::substr($key, $i, 2))->append('",');
        }

        $string = Str::of($string)->rtrim(',')->wrap('[', ']');

        return $string;
    }
}
