<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle;

use Kyzegs\SupabaseAuthBundle\Contract\SupabaseJwtVerifierInterface;
use Kyzegs\SupabaseAuthBundle\Security\SupabaseAccessTokenHandler;
use Kyzegs\SupabaseAuthBundle\Security\TestAccessTokenHandler;
use Kyzegs\SupabaseAuthBundle\Service\SupabaseJwtVerifier;
use Psr\Clock\ClockInterface;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * SupabaseAuthBundle — stateless authentication via Supabase-issued JWTs.
 *
 * Registers a Symfony access-token handler that verifies Supabase JWTs and
 * resolves the application user via a {@see Contract\SupabaseUserResolverInterface}
 * you provide. Uses the modern AbstractBundle API (Symfony 6.1+).
 *
 * Wire the firewall to the public handler id `supabase_auth.token_handler`:
 *
 *   security:
 *     firewalls:
 *       api:
 *         access_token:
 *           token_handler: supabase_auth.token_handler
 *
 * Example configuration (config/packages/supabase_auth.yaml):
 *
 *   supabase_auth:
 *     url: '%env(SUPABASE_URL)%'
 *     jwks_ttl: 600
 *     algorithms: ['RS256', 'ES256']
 *   when@test:
 *     supabase_auth:
 *       test_mode: true
 */
final class SupabaseAuthBundle extends AbstractBundle
{
    protected string $extensionAlias = 'supabase_auth';

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition
            ->rootNode()
                ->children()
                    ->scalarNode('url')
                        ->isRequired()
                        ->cannotBeEmpty()
                        ->info('The Supabase project URL, e.g. https://xxxx.supabase.co (no trailing slash).')
                        ->validate()
                            ->ifTrue(static fn (mixed $v): bool => !\is_string($v) || !\in_array(parse_url($v, PHP_URL_SCHEME), ['http', 'https'], true))
                            ->thenInvalid('The "url" must be an absolute http(s) URL, e.g. https://xxxx.supabase.co. Got %s.')
                        ->end()
                    ->end()
                    ->integerNode('jwks_ttl')
                        ->defaultValue(600)
                        ->min(0)
                        ->info('Seconds to cache the Supabase JWKS. Defaults to 600 (10 min), matching the Supabase edge cache.')
                    ->end()
                    ->integerNode('leeway')
                        ->defaultValue(0)
                        ->min(0)
                        ->info('Allowed clock skew, in seconds, applied to time-based claims (exp, iat, nbf).')
                    ->end()
                    ->scalarNode('audience')
                        ->defaultNull()
                        ->info('When set, the token "aud" claim must contain this value (Supabase uses "authenticated").')
                    ->end()
                    ->arrayNode('algorithms')
                        ->scalarPrototype()->end()
                        ->defaultValue(['RS256', 'ES256'])
                        ->requiresAtLeastOneElement()
                        ->validate()
                            ->ifTrue(static fn (array $v): bool => [] !== array_diff($v, ['RS256', 'ES256']))
                            ->thenInvalid('Unsupported algorithm(s) in "algorithms"; supported: RS256, ES256. Got %s.')
                        ->end()
                        ->info('Signature algorithms accepted from the JWKS. Supported: RS256, ES256.')
                    ->end()
                    ->booleanNode('test_mode')
                        ->defaultFalse()
                        ->info('When true, the public token handler accepts "{prefix}{identifier}" tokens instead of real JWTs.')
                    ->end()
                    ->scalarNode('test_token_prefix')
                        ->defaultValue('test-user-')
                        ->info('The bearer-token prefix recognised by the test handler when test_mode is enabled.')
                    ->end()
                ->end()
            ->end();
    }

    /**
     * @param array<string, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $services = $container->services()
            ->defaults()
            ->autowire()
            ->autoconfigure()
            ->private();

        // Config values are injected straight into the service definitions —
        // no intermediate container parameters are leaked into the application.
        $services->set(SupabaseJwtVerifier::class)
            ->arg('$clock', service(ClockInterface::class))
            ->arg('$supabaseUrl', $config['url'])
            ->arg('$jwksTtl', $config['jwks_ttl'])
            ->arg('$algorithms', $config['algorithms'])
            ->arg('$leeway', $config['leeway'])
            ->arg('$audience', $config['audience']);

        $services->alias(SupabaseJwtVerifierInterface::class, SupabaseJwtVerifier::class);

        $services->set(SupabaseAccessTokenHandler::class);

        $services->set(TestAccessTokenHandler::class)
            ->arg('$prefix', $config['test_token_prefix']);

        // Expose the active handler under a stable, public id so the
        // application firewall can reference it. The alias points at the test
        // handler when `test_mode` is enabled.
        $handler = $config['test_mode'] ? TestAccessTokenHandler::class : SupabaseAccessTokenHandler::class;

        $services->alias('supabase_auth.token_handler', $handler)->public();
    }
}
