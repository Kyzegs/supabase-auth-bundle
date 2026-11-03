<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Service;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Kyzegs\SupabaseAuthBundle\Contract\SupabaseJwtVerifierInterface;
use Kyzegs\SupabaseAuthBundle\Exception\InvalidTokenException;
use Kyzegs\SupabaseAuthBundle\Exception\VerificationUnavailableException;
use Psr\Clock\ClockInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Verifies JWTs issued by Supabase Auth using the project's JWKS.
 *
 * Failures are normalised so callers never have to reason about the underlying
 * JOSE/HTTP exception zoo: the token's fault is {@see InvalidTokenException}, the
 * server's (JWKS or configuration) is {@see VerificationUnavailableException}.
 *
 * @see https://supabase.com/docs/guides/auth/jwts
 */
final class SupabaseJwtVerifier implements SupabaseJwtVerifierInterface
{
    private const string SUPABASE_ISSUER_SUFFIX = '/auth/v1';

    private const int JWKS_TIMEOUT_SECONDS = 5;

    /**
     * Claims that MUST be present on every Supabase token. A token missing one
     * of these is rejected before the value checks run.
     *
     * @var list<string>
     */
    private const array MANDATORY_CLAIMS = ['iss', 'exp', 'sub'];

    /**
     * @var array<string, class-string<Algorithm>>
     */
    public const array SUPPORTED_ALGORITHMS = [
        'RS256' => RS256::class,
        'ES256' => ES256::class,
    ];

    /**
     * @param list<string> $algorithms Signature algorithms accepted from the JWKS
     * @param int          $jwksTtl    Seconds to cache the fetched JWKS
     * @param int          $leeway     Allowed clock skew, in seconds, applied to time-based claims
     * @param string|null  $audience   When set, the `aud` claim must contain this value
     */
    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
        private readonly string $supabaseUrl,
        private readonly int $jwksTtl = 600,
        private readonly array $algorithms = ['RS256', 'ES256'],
        private readonly int $leeway = 0,
        private readonly ?string $audience = null,
    ) {
    }

    public function verify(#[\SensitiveParameter] string $token): array
    {
        if ('' === trim($this->supabaseUrl)) {
            throw new VerificationUnavailableException('Supabase URL is not configured. Set SUPABASE_URL.');
        }

        // The URL is validated here, not in the bundle configuration, so that an
        // unresolved "%env(SUPABASE_URL)%" placeholder is accepted at compile time.
        if (!\in_array(parse_url($this->supabaseUrl, PHP_URL_SCHEME), ['http', 'https'], true)) {
            throw new VerificationUnavailableException(sprintf('Supabase URL must be an absolute http(s) URL, got "%s".', $this->supabaseUrl));
        }

        $issuer = rtrim($this->supabaseUrl, '/') . self::SUPABASE_ISSUER_SUFFIX;
        $jwksUrl = $issuer . '/.well-known/jwks.json';

        try {
            $jws = (new CompactSerializer())->unserialize($token);
        } catch (\Throwable $e) {
            throw new InvalidTokenException('Malformed token.', 0, $e);
        }

        $jwks = $this->getJwks($jwksUrl);

        $verifier = new JWSVerifier($this->buildAlgorithmManager());

        try {
            $verified = $verifier->verifyWithKeySet($jws, $jwks, 0);
        } catch (\Throwable $e) {
            // Thrown for a token without payload or with an unaccepted "alg" header.
            throw new InvalidTokenException('Invalid token signature.', 0, $e);
        }

        if (false === $verified) {
            throw new InvalidTokenException('Invalid token signature.');
        }

        try {
            /** @var array<string, mixed> $claims */
            $claims = json_decode((string) $jws->getPayload(), true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new InvalidTokenException('Invalid token payload.', 0, $e);
        }

        if (!\is_array($claims)) {
            throw new InvalidTokenException('Invalid token payload.');
        }

        try {
            // The checker skips a claim that is absent, so a configured audience must also be mandatory.
            $this->buildClaimChecker($issuer)->check($claims, null === $this->audience ? self::MANDATORY_CLAIMS : [...self::MANDATORY_CLAIMS, 'aud']);
        } catch (\Throwable $e) {
            throw new InvalidTokenException('Token claim check failed.', 0, $e);
        }

        return $claims;
    }

    private function buildAlgorithmManager(): AlgorithmManager
    {
        if ([] === $this->algorithms) {
            throw new VerificationUnavailableException('No signature algorithms configured.');
        }

        $instances = [];
        foreach ($this->algorithms as $algorithm) {
            if (!isset(self::SUPPORTED_ALGORITHMS[$algorithm])) {
                throw new VerificationUnavailableException(sprintf('Unsupported signature algorithm "%s".', $algorithm));
            }

            $instances[] = new (self::SUPPORTED_ALGORITHMS[$algorithm])();
        }

        return new AlgorithmManager($instances);
    }

    private function buildClaimChecker(string $issuer): ClaimCheckerManager
    {
        $checkers = [
            new ExpirationTimeChecker($this->clock, $this->leeway),
            new IssuedAtChecker($this->clock, $this->leeway),
            new NotBeforeChecker($this->clock, $this->leeway),
            new IssuerChecker([$issuer]),
        ];

        if (null !== $this->audience) {
            $checkers[] = new AudienceChecker($this->audience);
        }

        return new ClaimCheckerManager($checkers);
    }

    private function getJwks(string $url): JWKSet
    {
        $key = sprintf('supabase_jwks_%s', md5($url));

        try {
            // The fetch must stay out of the cache callback: under FPM that callback holds the
            // stampede lock, and an outage would queue each worker behind the previous timeouts.
            $cached = $this->cache->get($key, static function (ItemInterface $item, bool &$save): null {
                $save = false;

                return null;
            });

            if ($cached instanceof JWKSet) {
                return $cached;
            }

            // Failures are not cached, so every request of an outage waits this long.
            // "timeout" only limits idle time; "max_duration" limits the whole request.
            $response = $this->http->request('GET', $url, [
                'timeout' => self::JWKS_TIMEOUT_SECONDS,
                'max_duration' => self::JWKS_TIMEOUT_SECONDS,
            ]);

            $jwks = JWKSet::createFromJson($response->getContent());

            // Thrown before the cache write, so the empty set is not cached either.
            if (0 === $jwks->count()) {
                throw new \UnexpectedValueException('The key set is empty.');
            }

            // ChainAdapter stores expiresAfter(0) as "never expires", which would trust a revoked key forever.
            if (0 === $this->jwksTtl) {
                return $jwks;
            }

            return $this->cache->get($key, function (ItemInterface $item) use ($jwks): JWKSet {
                $item->expiresAfter($this->jwksTtl);

                return $jwks;
            });
        } catch (\Throwable $e) {
            throw new VerificationUnavailableException('Unable to load the Supabase JWKS.', 0, $e);
        }
    }
}
