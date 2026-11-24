<?php

namespace WeDevsSecureSettings;

/** Stable configuration reasons; callers must not display arbitrary exception messages. */
final class Configuration_Exception extends \RuntimeException {
    public const MISSING_SODIUM = 1;
    public const INVALID_KEY = 2;
}

/** Authenticated encryption for recoverable service credentials. */
final class Secret_Cipher {
    private const PREFIX = 'wsa-secret:v1:';

    /** @var callable */
    private $key_provider;

    /** The provider returns a base64-encoded, independently generated 32-byte key. */
    public function __construct( ?callable $key_provider = null ) {
        $this->key_provider = $key_provider ?? static function () {
            return defined( 'WSA_SETTINGS_SECRET_KEY' ) ? WSA_SETTINGS_SECRET_KEY : '';
        };
    }

    private function key(): string {
        if ( ! function_exists( 'sodium_crypto_aead_xchacha20poly1305_ietf_encrypt' ) ) {
            throw new Configuration_Exception( 'The PHP Sodium extension is required.', Configuration_Exception::MISSING_SODIUM );
        }
        $encoded = call_user_func( $this->key_provider );
        $key = is_string( $encoded ) ? base64_decode( $encoded, true ) : false;
        if ( false === $key || 32 !== strlen( $key ) ) {
            throw new Configuration_Exception( 'Configure a valid WSA_SETTINGS_SECRET_KEY.', Configuration_Exception::INVALID_KEY );
        }
        return $key;
    }

    public function encrypt( string $plaintext, string $context ): string {
        $key = $this->key();
        try {
            $nonce = random_bytes( SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES );
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext, self::PREFIX . $context, $nonce, $key
            );
            return self::PREFIX . base64_encode( $nonce . $ciphertext );
        } finally {
            sodium_memzero( $key );
        }
    }

    /** Reject plaintext, unknown versions, tampering, and credentials copied between fields. */
    public function decrypt( string $stored, string $context ): string {
        $key = $this->key();
        try {
            if ( ! str_starts_with( $stored, self::PREFIX ) ) {
                throw new \RuntimeException( 'The stored credential is not a supported encrypted value.' );
            }
            $payload = base64_decode( substr( $stored, strlen( self::PREFIX ) ), true );
            $nonce_size = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
            if ( false === $payload || strlen( $payload ) < $nonce_size + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES ) {
                throw new \RuntimeException( 'The stored credential is invalid.' );
            }
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                substr( $payload, $nonce_size ), self::PREFIX . $context,
                substr( $payload, 0, $nonce_size ), $key
            );
            if ( false === $plaintext ) {
                throw new \RuntimeException( 'The stored credential could not be authenticated.' );
            }
            return $plaintext;
        } finally {
            sodium_memzero( $key );
        }
    }
}
