<?php
declare(strict_types=1);
namespace Componenta\Auth\Http\Tests;
use PHPUnit\Framework\TestCase;
final class ArchitectureTest extends TestCase
{
    public function testSourceDoesNotDependOnLegacySessionNamespace(): void
    {
        $it=new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(dirname(__DIR__).'/src'));
        foreach ($it as $file) {
            if (!$file->isFile() || $file->getExtension()!=='php') continue;
            $contents=file_get_contents($file->getPathname());
            self::assertIsString($contents);
            self::assertStringNotContainsString('Componenta\\Auth\\Session\\',$contents,$file->getPathname());
        }
    }
}
