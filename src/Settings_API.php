<?php

namespace WeDevsSecureSettings;

require_once __DIR__ . '/Secret_Cipher.php';

/** Load the original WeDevs_Settings_API class before this file. */
class Settings_API extends \WeDevs_Settings_API {
    private const INVALID_INPUT = 1;
    private const TOO_LONG = 2;
    private const CONFLICTING_ACTIONS = 3;

    private Secret_Cipher $cipher;

    /** Exact outputs produced in this request, to support WordPress's repeated sanitization. */
    private array $accepted = array();

    public function __construct( ?Secret_Cipher $cipher = null ) {
        $this->cipher = $cipher ?? new Secret_Cipher();
        parent::__construct();
    }

    public function admin_init() {
        foreach ( $this->settings_sections as $section ) {
            if ( $this->has_secrets( $section['id'] ) ) {
                add_option( $section['id'], array(), '', false );
                // WordPress 6.6+: also handles options created before this extension.
                wp_set_option_autoload( $section['id'], false );
            }
        }
        parent::admin_init();
    }

    private function has_secrets( string $section ): bool {
        foreach ( $this->settings_fields[ $section ] ?? array() as $field ) {
            if ( 'secret' === ( $field['type'] ?? '' ) ) {
                return true;
            }
        }
        return false;
    }

    private function context( string $section, string $name ): string {
        return json_encode( array( get_current_blog_id(), $section, $name ), JSON_THROW_ON_ERROR );
    }

    private function error( string $section, string $name, \Throwable $error ): void {
        // Only fixed messages for known reasons. Never expose arbitrary exception messages.
        $reason = __( 'Encryption failed. Check the server configuration.', 'wedevs-secure-settings' );
        if ( $error instanceof Configuration_Exception ) {
            if ( Configuration_Exception::INVALID_KEY === $error->getCode() ) {
                $reason = __( 'WSA_SETTINGS_SECRET_KEY is missing or invalid. Configure a base64-encoded 32-byte encryption key in wp-config.php. If using getenv(), the environment variable must be available to the PHP process serving WordPress.', 'wedevs-secure-settings' );
            } elseif ( Configuration_Exception::MISSING_SODIUM === $error->getCode() ) {
                $reason = __( 'PHP Sodium encryption is unavailable. Enable Sodium for the PHP process serving WordPress.', 'wedevs-secure-settings' );
            }
        } elseif ( $error instanceof \InvalidArgumentException ) {
            switch ( $error->getCode() ) {
                case self::INVALID_INPUT:
                    $reason = __( 'Invalid credential submission. Use the secret field renderer; a replacement must be submitted as field[value].', 'wedevs-secure-settings' );
                    break;
                case self::TOO_LONG:
                    $reason = __( 'The credential exceeds the 4096-byte limit.', 'wedevs-secure-settings' );
                    break;
                case self::CONFLICTING_ACTIONS:
                    $reason = __( 'Uncheck Delete saved credential when entering a replacement.', 'wedevs-secure-settings' );
                    break;
            }
        }
        add_settings_error(
            $section, 'wsa_secret_' . $name,
            sprintf( __( 'Could not update credential "%s". Its previous value was kept.', 'wedevs-secure-settings' ), esc_html( $name ) ) . ' ' . $reason
        );
    }

    /** Invoked by register_setting through sanitize_option_{section}; do not call directly. */
    public function sanitize_options( $input ) {
        $hook = current_filter();
        $prefix = 'sanitize_option_';
        if ( ! str_starts_with( $hook, $prefix ) ) {
            throw new \LogicException( 'Save through the WordPress Options API.' );
        }
        $section = substr( $hook, strlen( $prefix ) );
        if ( ! isset( $this->settings_fields[ $section ] ) ) {
            throw new \LogicException( 'Unregistered settings section.' );
        }
        $old = get_option( $section, array() );
        $old = is_array( $old ) ? $old : array();
        $capability = apply_filters( 'option_page_capability_' . $section, 'manage_options' );
        if ( ! current_user_can( $capability ) ) {
            add_settings_error( $section, 'wsa_forbidden', __( 'You cannot change these settings.', 'wedevs-secure-settings' ) );
            return $old;
        }
        if ( null === $input ) {
            return $old;
        }
        if ( ! is_array( $input ) ) {
            add_settings_error( $section, 'wsa_invalid', __( 'Invalid settings submission. Previous settings were kept.', 'wedevs-secure-settings' ) );
            return $old;
        }
        $output = $old;
        foreach ( $this->settings_fields[ $section ] as $field ) {
            $name = $field['name'];
            if ( ! array_key_exists( $name, $input ) ) {
                continue;
            }
            if ( 'secret' !== ( $field['type'] ?? '' ) ) {
                $callback = $field['sanitize_callback'] ?? null;
                $output[ $name ] = is_callable( $callback ) ? call_user_func( $callback, $input[ $name ] ) : $input[ $name ];
                continue;
            }
            $context = $this->context( $section, $name );
            try {
                $output[ $name ] = $this->sanitize_secret( $input[ $name ], $old[ $name ] ?? '', $context );
                $this->accepted[ $context ][ $output[ $name ] ] = true;
            } catch ( \Throwable $error ) {
                $this->error( $section, $name, $error );
            }
        }
        return $output;
    }

    private function sanitize_secret( $input, $old, string $context ): string {
        // A string is allowed only if it is unchanged stored data or our exact earlier output.
        // Merely looking like ciphertext is never sufficient to bypass encryption.
        if ( is_string( $input ) && (
            ( is_string( $old ) && hash_equals( $old, $input ) ) ||
            isset( $this->accepted[ $context ][ $input ] )
        ) ) {
            return $input;
        }
        if ( ! is_array( $input ) || array_diff( array_keys( $input ), array( 'value', 'delete' ) ) ) {
            throw new \InvalidArgumentException( 'Invalid credential submission.', self::INVALID_INPUT );
        }
        $value = $input['value'] ?? '';
        $delete = $input['delete'] ?? '0';
        if ( ! is_string( $value ) || ! in_array( $delete, array( '0', '1' ), true ) ) {
            throw new \InvalidArgumentException( 'Invalid credential submission.', self::INVALID_INPUT );
        }
        if ( strlen( $value ) > 4096 ) {
            throw new \InvalidArgumentException( 'Credential too long.', self::TOO_LONG );
        }
        if ( '1' === $delete ) {
            if ( '' !== $value ) {
                throw new \InvalidArgumentException( 'Choose replacement or deletion.', self::CONFLICTING_ACTIONS );
            }
            return '';
        }
        if ( '' === $value ) {
            if ( ! is_string( $old ) ) {
                throw new \RuntimeException( 'Invalid stored credential.' );
            }
            return $old;
        }
        // Preserve spaces, percent sequences, quotes, and backslashes in credentials.
        // options.php has already unslashed its input; do not unslash a second time.
        return $this->cipher->encrypt( $value, $context );
    }

    public function callback_secret( $args ) {
        $section = $args['section'];
        $name = $args['id'];
        $id = $section . '[' . $name . ']';
        $stored = parent::get_option( $name, $section, '' );
        $status = '' === $stored ? __( 'No credential saved.', 'wedevs-secure-settings' ) : __( 'A value is saved. Leave blank to keep it.', 'wedevs-secure-settings' );
        echo '<input type="password" class="regular-text" id="' . esc_attr( $id ) . '" name="' . esc_attr( $id . '[value]' ) . '" value="" autocomplete="new-password" spellcheck="false" autocapitalize="none" aria-describedby="' . esc_attr( $id . '-status' ) . '" />';
        echo '<p class="description" id="' . esc_attr( $id . '-status' ) . '">' . esc_html( $status ) . '</p>';
        echo '<label><input type="checkbox" name="' . esc_attr( $id . '[delete]' ) . '" value="1" /> ' . esc_html__( 'Delete saved credential', 'wedevs-secure-settings' ) . '</label>';
        if ( ! empty( $args['desc'] ) ) {
            echo '<p class="description">' . wp_kses_post( $args['desc'] ) . '</p>';
        }
    }

    /** Server-side use only. Returns an empty string when unset, or WP_Error on failure. */
    public function get_secret( string $name, string $section ) {
        $registered = false;
        foreach ( $this->settings_fields[ $section ] ?? array() as $field ) {
            if ( $name === $field['name'] && 'secret' === ( $field['type'] ?? '' ) ) {
                $registered = true;
                break;
            }
        }
        if ( ! $registered ) {
            return new \WP_Error( 'wsa_unknown_secret', 'Unregistered credential field.' );
        }
        $stored = parent::get_option( $name, $section, '' );
        if ( '' === $stored ) {
            return '';
        }
        try {
            if ( ! is_string( $stored ) ) {
                throw new \RuntimeException( 'Invalid stored credential.' );
            }
            return $this->cipher->decrypt( $stored, $this->context( $section, $name ) );
        } catch ( \Throwable $error ) {
            return new \WP_Error( 'wsa_secret_unavailable', 'The credential could not be decrypted. Check the encryption key or replace the credential.' );
        }
    }
}
