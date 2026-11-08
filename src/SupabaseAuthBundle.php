<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle;

use Kyzegs\SupabaseAuthBundle\Contract\SupabaseJwtVerifierInterface;
use Kyzegs\SupabaseAuthBundle\Security\SupabaseAccessTokenHandler;
use Kyzegs\SupabaseAuthBundle\Security\TestAccessTokenHandler;
use Kyzegs\SupabaseAuthBundle\Service\SupabaseJwtVerifier;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

/**
 * Stateless authentication via Supabase-issued JWTs. The README covers
 * configuration and firewall wiring.
 */
final class SupabaseAuthBundle extends AbstractBundle
{
    protected string $extensionAlias = 'supabase_auth';

    public function configure(DefinitionConfigurator $definition): void
    {
        $algorithms = array_keys(SupabaseJwtVerifier::SUPPORTED_ALGORITHMS);

        $definition
            ->rootNode()
                ->children()
                    ->scalarNode('url')
                        ->isRequired()
                        ->cannotBeEmpty()
                        ->info('The Supabase project URL, e.g. https://xxxx.supabase.co. Must be an absolute http(s) URL; validated at runtime so an %env()% value is accepted.')
                    ->end()
                    ->integerNode('jwks_ttl')
                        ->defaultValue(600)
                        ->min(0)
                        ->info('Seconds to cache the Supabase JWKS. Defaults to 600 (10 min), matching the Supabase edge cache.')
                    ->end()
                    ->integerNode('leeway')
                        ->defaultValue(60)
                        ->min(0)
                        ->info('Allowed clock skew, in seconds, applied to time-based claims (exp, iat, nbf). At 0, a fresh token issued by a clock ahead of this server answers 401.')
                    ->end()
                    ->scalarNode('audience')
                        ->defaultNull()
                        ->info('When set, the token must have an "aud" claim containing this value (Supabase uses "authenticated").')
                    ->end()
                    ->arrayNode('algorithms')
                        ->scalarPrototype()->end()
                        ->defaultValue($algorithms)
                        ->requiresAtLeastOneElement()
                        ->validate()
                            ->ifTrue(static fn (array $v): bool => [] !== array_filter($v, static fn (mixed $a): bool => !\in_array($a, $algorithms, true)))
                            ->thenInvalid(sprintf('Unsupported algorithm(s) in "algorithms"; supported: %s. Got %%s.', implode(', ', $algorithms)))
                        ->end()
                        ->info(sprintf('Signature algorithms accepted from the JWKS. Supported: %s.', implode(', ', $algorithms)))
                    ->end()
                    ->booleanNode('test_mode')
                        ->defaultFalse()
                        ->info('When true, the public token handler accepts "{prefix}{identifier}" tokens instead of real JWTs. Must be a literal boolean, and is only allowed in the "test" environment.')
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
        // At compile time an %env()% value is a truthy placeholder string, whatever it resolves to later.
        if (!\is_bool($config['test_mode'])) {
            throw new InvalidConfigurationException('"supabase_auth.test_mode" must be a literal boolean, not an %env()% value. Set it under "when@test".');
        }

        // The test handler lets any caller sign in as any user.
        if ($config['test_mode'] && 'test' !== $container->env()) {
            throw new InvalidConfigurationException('"supabase_auth.test_mode" can only be enabled in the "test" environment. Set it under "when@test".');
        }

        $services = $container->services()
            ->defaults()
            ->autowire()
            ->autoconfigure()
            ->private();

        $services->set(SupabaseJwtVerifier::class)
            ->arg('$supabaseUrl', $config['url'])
            ->arg('$jwksTtl', $config['jwks_ttl'])
            ->arg('$algorithms', $config['algorithms'])
            ->arg('$leeway', $config['leeway'])
            ->arg('$audience', $config['audience']);

        $services->alias(SupabaseJwtVerifierInterface::class, SupabaseJwtVerifier::class);

        $services->set(SupabaseAccessTokenHandler::class);

        $services->set(TestAccessTokenHandler::class)
            ->arg('$prefix', $config['test_token_prefix']);

        // Applications point their firewall at this id, whichever handler is active.
        $handler = $config['test_mode'] ? TestAccessTokenHandler::class : SupabaseAccessTokenHandler::class;

        $services->alias('supabase_auth.token_handler', $handler)->public();
    }
}
