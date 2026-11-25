<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Tests;

use Componenta\Auth\Denied\Unauthorized;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactory;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DeniedResponseFactoryTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function denialCodes(): iterable
    {
        yield 'zero' => ['0'];
        yield 'decimal code' => ['42'];
        yield 'leading zero' => ['042'];
        yield 'named code' => ['custom_denial'];
    }

    #[DataProvider('denialCodes')]
    public function testEveryValidCodeCanHaveACustomStatus(string $code): void
    {
        $reason = new readonly class($code) implements DeniedReasonInterface {
            public function __construct(public string $code, public array $attributes = []) {}
        };
        $factory = new DeniedResponseFactory(new Psr17Factory(), [$code => 429]);

        $response = $factory->create($reason);

        self::assertSame(429, $response->getStatusCode());
        self::assertSame(
            ['error' => $code],
            json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR),
        );
    }

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
