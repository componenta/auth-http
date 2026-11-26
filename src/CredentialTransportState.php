<?php
declare(strict_types=1);
namespace Componenta\Auth\Http;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
final class CredentialTransportState
{
    /** @var array<int, PayloadStorageInterface> */
    private array $storages = [];
    /** @var array<int, array{storage: PayloadStorageInterface, payload: object}> */
    private array $queued = [];
    /** @var array<int, \Closure(): void> */
    private array $discardCallbacks = [];
    private int $lastRegistrationId = 0;
    private bool $clear = false;
    public bool $empty { get => !$this->clear && $this->queued === []; }
    public bool $cleared { get => $this->clear; }
    /** @return array{storages:string, queued:string, discardCallbacks:string, cleared:bool} */
    public function __debugInfo(): array
    {
        return [
            'storages' => '[REDACTED]',
            'queued' => '[REDACTED]',
            'discardCallbacks' => '[REDACTED]',
            'cleared' => $this->clear,
        ];
    }
    public function register(PayloadStorageInterface $storage): void { $this->storages[spl_object_id($storage)] = $storage; }
    public function queue(PayloadStorageInterface $storage, object $payload): void
    {
        $this->register($storage);
        if (!$this->clear) $this->queued[++$this->lastRegistrationId] = ['storage' => $storage, 'payload' => $payload];
    }
    public function onDiscard(#[\SensitiveParameter] \Closure $callback): void
    {
        if ($this->clear) { $callback(); return; }
        $this->discardCallbacks[++$this->lastRegistrationId] = $callback;
    }
    /**
     * Captures a one-shot rollback of later registrations still pending here.
     * Explicit global cancellation and in-flight publication remain authoritative.
     *
     * @internal Used to isolate a soft-failed authentication candidate.
     * @return \Closure(): void
     */
    public function checkpoint(): \Closure
    {
        $watermark = $this->lastRegistrationId;
        $used = false;

        return function () use ($watermark, &$used): void {
            if ($used) return;
            $used = true;
            $this->discardAfter($watermark);
        };
    }
    public function discardQueued(): void
    {
        $this->discardAfter(0);
    }
    private function discardAfter(int $watermark): void
    {
        foreach ($this->queued as $id => $entry) {
            if ($id > $watermark) unset($this->queued[$id]);
        }
        $callbacks = [];
        foreach ($this->discardCallbacks as $id => $callback) {
            if ($id <= $watermark) continue;
            $callbacks[] = $callback;
            unset($this->discardCallbacks[$id]);
        }
        // Detach all selected work before callbacks can queue or cancel more work.
        $failure = null;
        foreach (array_reverse($callbacks) as $callback) {
            try { $callback(); } catch (\Throwable $exception) { $failure ??= $exception; }
        }
        if ($failure !== null) throw $failure;
    }
    /** Makes credential removal terminal for this request, including in-flight publication. */
    public function clear(#[\SensitiveParameter] PayloadStorageInterface $storage): void
    {
        $this->register($storage); $this->clear = true; $this->discardQueued();
    }
    public function apply(
        #[\SensitiveParameter] ServerRequestInterface $request,
        #[\SensitiveParameter] ResponseInterface $response,
    ): ResponseInterface {
        if ($this->clear) {
            $removed = [];
            do {
                foreach ($this->storages as $id => $storage) {
                    if (isset($removed[$id])) continue;
                    $removed[$id] = true;
                    $response = $storage->remove($request, $response);
                }
                $response = CredentialResponseHeaders::apply($response);
                // Removal and header callbacks may register another transport.
            } while (count($removed) !== count($this->storages));

            return $response;
        }
        if ($this->queued === []) return $response;
        // Once publication starts, replacement concerns pending work, not
        // the batch currently being committed and its compensation callbacks.
        $queued = $this->queued;
        $discardCallbacks = $this->discardCallbacks;
        $this->queued = [];
        $this->discardCallbacks = [];
        try {
            foreach ($queued as $entry) {
                $response = $entry['storage']->store($request, $response, $entry['payload']);
                if ($this->cleared) break;
            }
            if (!$this->cleared) $response = CredentialResponseHeaders::apply($response);
        } catch (\Throwable $exception) {
            $this->discardCallbacks = $discardCallbacks + $this->discardCallbacks;
            $this->discardQueued();
            throw $exception;
        }
        // A terminal clear may arrive through a storage or response callback.
        // It cancels the active batch too, unlike replacement of pending work.
        if ($this->cleared) {
            $this->discardCallbacks = $discardCallbacks + $this->discardCallbacks;
            $this->discardQueued();

            return $this->apply($request, $response);
        }

        return $response;
    }
}
