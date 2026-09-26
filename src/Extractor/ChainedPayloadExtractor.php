<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Extractor;

use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class ChainedPayloadExtractor implements PayloadExtractorInterface
{
    /** @var list<PayloadExtractorInterface> */
    private array $extractors;

    public function __construct(PayloadExtractorInterface ...$extractors)
    {
        $this->extractors = array_values($extractors);
    }

    #[\Override]
    public function extract(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ?object {
        foreach ($this->extractors as $extractor) {
            $payload = $extractor->extract($request);

            if ($payload !== null) {
                return $payload;
            }
        }

        return null;
    }

    /**
     * Returns every credential candidate in configured extractor order.
     *
     * @return list<object>
     */
    public function candidates(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): array {
        $payloads = [];

        foreach ($this->extractors as $extractor) {
            $payload = $extractor->extract($request);

            if ($payload !== null) {
                $payloads[] = $payload;
            }
        }

        return $payloads;
    }
}
