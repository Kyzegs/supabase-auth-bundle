<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Tests\Functional\App;

use Symfony\Component\HttpClient\Response\MockResponse;

final class StubJwksEndpoint
{
    public ?string $body = null;

    public int $requests = 0;

    public function __invoke(): MockResponse
    {
        ++$this->requests;

        return null === $this->body
            ? new MockResponse(info: ['error' => 'Supabase is down'])
            : new MockResponse($this->body);
    }
}
