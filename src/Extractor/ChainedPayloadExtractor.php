<?php
declare(strict_types=1);
namespace Componenta\Auth\Http\Extractor;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;
final readonly class ChainedPayloadExtractor implements PayloadExtractorInterface
{
    /** @var list<PayloadExtractorInterface> */
    private array $extractors;
    public function __construct(PayloadExtractorInterface ...$extractors) { $this->extractors=array_values($extractors); }
    public function extract(ServerRequestInterface $request): ?object
    {
        foreach ($this->extractors as $extractor) if (($payload=$extractor->extract($request))!==null) return $payload;
        return null;
    }
}
