<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Tests;

use Componenta\Auth\Denied\Unauthorized;
use Componenta\Auth\Http\DeniedResponseFactory;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;

final class DeniedResponseFactoryTest extends TestCase
{
    public function testMappedStatusRemainsValidatedWhenInputReferenceChanges(): void
    {
        $status = 403;
        $factory = new DeniedResponseFactory(
            new Psr17Factory(),
            ['unauthorized' => &$status],
        );

        $status = 200;
        $response = $factory->create(new Unauthorized());

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('{"error":"unauthorized"}', (string) $response->getBody());
    }

    public function testSuccessfulStatusCannotBeConfiguredForDenial(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new DeniedResponseFactory(new Psr17Factory(), ['unauthorized' => 200]);
    }
}
