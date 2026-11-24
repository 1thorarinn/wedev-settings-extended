<?php
/** Standalone regression harness using the REAL upstream class with small WordPress stubs. */

error_reporting( E_ALL );
set_error_handler( static function ( $severity, $message, $file, $line ) {
    throw new ErrorException( $message, 0, $severity, $file, $line );
} );

$upstream = $argv[1] ?? '';
if ( ! is_file( $upstream ) ) {
    fwrite( STDERR, "Usage: php tests/run.php /path/to/upstream/class.settings-api.php\n" );
    exit( 1 );
}

$options = $filters = $hooks = $errors = $autoload = $registered = $renderers = array();
$authorized = true;
$blog_id = 1;
$assertions = 0;

function add_action( ...$args ) {}
function add_filter( $hook, $callback, ...$args ) { $GLOBALS['filters'][ $hook ][] = $callback; }
function current_filter() { return end( $GLOBALS['hooks'] ) ?: ''; }
function apply_filters( $hook, $value, ...$args ) {
    $GLOBALS['hooks'][] = $hook;
    try {
        foreach ( $GLOBALS['filters'][ $hook ] ?? array() as $callback ) {
            $value = $callback( $value, ...$args );
        }
        return $value;
    } finally { array_pop( $GLOBALS['hooks'] ); }
}
function register_setting( $group, $name, $args ) {
    $GLOBALS['registered'][ $name ] = $args;
    add_filter( 'sanitize_option_' . $name, is_callable( $args ) ? $args : $args['sanitize_callback'] );
}
function add_settings_section( ...$args ) {}
function add_settings_field( $id, $label, $callback, $section, $group, $args ) {
    $GLOBALS['renderers'][ $id ] = array( $callback, $args );
}
function get_option( $name, $default = false ) { return $GLOBALS['options'][ $name ] ?? $default; }
function add_option( $name, $value = '', $deprecated = '', $autoload = null ) {
    if ( array_key_exists( $name, $GLOBALS['options'] ) ) { return false; }
    $GLOBALS['options'][ $name ] = apply_filters( 'sanitize_option_' . $name, $value );
    $GLOBALS['autoload'][ $name ] = $autoload;
    return true;
}
function wp_set_option_autoload( $name, $value ) { $GLOBALS['autoload'][ $name ] = $value; }
function update_option( $name, $value ) {
    $value = apply_filters( 'sanitize_option_' . $name, $value );
    if ( ! array_key_exists( $name, $GLOBALS['options'] ) ) {
        return add_option( $name, $value ); // Core can sanitize twice on initial creation.
    }
    $GLOBALS['options'][ $name ] = $value;
    return true;
}
function current_user_can( $capability ) { return $GLOBALS['authorized'] && 'manage_options' === $capability; }
function get_current_blog_id() { return $GLOBALS['blog_id']; }
function add_settings_error( $setting, $code, $message, $type = 'error' ) { $GLOBALS['errors'][] = $message; }
function __( $message, $domain = '' ) { return $message; }
function esc_attr( $value ) { return htmlspecialchars( (string) $value, ENT_QUOTES, 'UTF-8' ); }
function esc_html( $value ) { return esc_attr( $value ); }
function esc_html__( $value, $domain = '' ) { return esc_html( $value ); }
function wp_kses_post( $value ) { return strip_tags( $value, '<strong><em>' ); }
class WP_Error {
    public function __construct( public $code, public $message ) {}
}
function check( $condition, $message ) {
    ++$GLOBALS['assertions'];
    if ( ! $condition ) { throw new RuntimeException( $message ); }
}
function throws( callable $callback, $message ) {
    try { $callback(); } catch ( RuntimeException $error ) { check( true, $message ); return; }
    check( false, $message );
}

require $upstream;
require dirname( __DIR__ ) . '/src/Settings_API.php';

use WeDevsSecureSettings\Secret_Cipher;
use WeDevsSecureSettings\Settings_API;

throws( fn() => ( new Secret_Cipher() )->encrypt( 'test', 'context' ), 'Default provider rejects missing configuration' );

$key = base64_encode( random_bytes( 32 ) );
$cipher = new Secret_Cipher( static function () use ( &$key ) { return $key; } );
$secret = '  test-credential+%2F<>&"\'\\tail  ';
$encrypted = $cipher->encrypt( $secret, 'test-context' );
check( $secret === $cipher->decrypt( $encrypted, 'test-context' ), 'Exact credential round trip' );
check( $encrypted !== $cipher->encrypt( $secret, 'test-context' ), 'Random nonce per encryption' );
throws( fn() => $cipher->decrypt( $encrypted, 'other-context' ), 'Context binding' );
$tampered = $encrypted;
$tampered[25] = 'A' === $tampered[25] ? 'B' : 'A';
throws( fn() => $cipher->decrypt( $tampered, 'test-context' ), 'Tamper detection' );
foreach ( array( 'plaintext', 'wsa-secret:v2:anything', 'wsa-secret:v1:***', 'wsa-secret:v1:YQ==' ) as $bad ) {
    throws( fn() => $cipher->decrypt( $bad, 'test-context' ), 'Malformed ciphertext rejected' );
}
$correct_key = $key;
$key = base64_encode( random_bytes( 32 ) );
throws( fn() => $cipher->decrypt( $encrypted, 'test-context' ), 'Wrong key rejected' );
foreach ( array( '', '***', base64_encode( 'too short' ) ) as $key ) {
    throws( fn() => $cipher->encrypt( $secret, 'test-context' ), 'Invalid key fails closed' );
}
$key = $correct_key;

$api = new Settings_API( $cipher );
$api->set_sections( array(
    array( 'id' => 'service', 'title' => 'Service' ),
    array( 'id' => 'other', 'title' => 'Other' ),
) );
$fields = array(
    array( 'name' => 'key', 'type' => 'secret', 'label' => 'API key' ),
    array( 'name' => 'password', 'type' => 'secret', 'label' => 'Password' ),
    array( 'name' => 'text', 'type' => 'text', 'sanitize_callback' => 'strtoupper' ),
);
$api->set_fields( array( 'service' => $fields, 'other' => array(
    array( 'name' => 'key', 'type' => 'secret' ),
    array( 'name' => 'text', 'type' => 'text', 'sanitize_callback' => 'strtolower' ),
) ) );
$api->admin_init();
check( false === $autoload['service'] && false === $autoload['other'], 'Secret sections do not autoload' );
check( isset( $registered['service'], $renderers['service[key]'] ), 'Upstream registration works' );
check( '' === $api->get_secret( 'key', 'service' ), 'Unset credential is empty' );
check( $api->get_secret( 'text', 'service' ) instanceof WP_Error, 'Non-secret reads rejected' );

update_option( 'service', array( 'key' => array( 'value' => $secret ), 'text' => 'mixed', 'unknown' => 'discard' ) );
$saved = get_option( 'service' );
check( $secret === $api->get_secret( 'key', 'service' ), 'Save and explicit server-side read' );
check( ! str_contains( serialize( $saved ), $secret ), 'No plaintext in stored option' );
check( $saved['key'] === $api->get_option( 'key', 'service' ), 'Normal getter returns ciphertext' );
check( 'MIXED' === $saved['text'] && ! isset( $saved['unknown'] ), 'Normal sanitizer and field allowlist' );
update_option( 'other', array( 'text' => 'MIXED', 'key' => array( 'value' => 'other-secret' ) ) );
check( 'mixed' === get_option( 'other' )['text'], 'Sanitizers scoped by section despite duplicate names' );

foreach ( array( array( 'key' => array( 'value' => '' ) ), array( 'text' => 'changed' ), null ) as $submission ) {
    update_option( 'service', $submission );
    check( $saved['key'] === get_option( 'service' )['key'], 'Blank/missing input preserves ciphertext' );
}
foreach ( array( 'raw-plaintext', 'wsa-secret:v1:pretend', array( 'value' => array() ), array( 'value' => str_repeat( 'a', 4097 ) ), array( 'value' => 'new', 'delete' => '1' ), array( 'delete' => array() ), array( 'extra' => 'bad' ) ) as $bad ) {
    $before_errors = count( $errors );
    update_option( 'service', array( 'key' => $bad ) );
    check( $saved['key'] === get_option( 'service' )['key'] && count( $errors ) === $before_errors + 1, 'Invalid input preserves credential and reports error' );
}
check( str_contains( end( $errors ), 'field[value]' ), 'Malformed input notice identifies expected submission shape' );
update_option( 'service', array( 'key' => array( 'value' => 'replacement', 'delete' => '1' ) ) );
check( str_contains( end( $errors ), 'Uncheck Delete saved credential' ), 'Conflicting action notice explains how to replace' );
update_option( 'service', array( 'key' => array( 'value' => str_repeat( 'x', 4097 ) ) ) );
check( str_contains( end( $errors ), '4096-byte limit' ), 'Oversize input notice explains limit' );
$key = '';
update_option( 'service', array( 'key' => array( 'value' => 'replacement' ) ) );
check( $saved['key'] === get_option( 'service' )['key'], 'Failed encryption preserves old credential' );
check( str_contains( end( $errors ), 'WSA_SETTINGS_SECRET_KEY is missing or invalid' ), 'Missing key notice explains configuration failure' );
check( $api->get_secret( 'key', 'service' ) instanceof WP_Error, 'Missing key returns error' );
$key = $correct_key;

ob_start();
[ $renderer, $args ] = $renderers['service[key]'];
$renderer( $args );
$html = ob_get_clean();
check( ! str_contains( $html, $secret ) && ! str_contains( $html, $saved['key'] ), 'HTML includes neither secret nor ciphertext' );
check( str_contains( $html, 'value=""' ) && str_contains( $html, 'service[key][delete]' ), 'Blank input and explicit delete control' );

$authorized = false;
update_option( 'service', array( 'key' => array( 'delete' => '1' ), 'text' => 'unauthorized' ) );
check( $saved['key'] === get_option( 'service' )['key'] && 'CHANGED' === get_option( 'service' )['text'], 'Capability check protects all settings' );
$authorized = true;
update_option( 'service', array( 'key' => array( 'value' => '0' ) ) );
check( '0' === $api->get_secret( 'key', 'service' ), 'String zero is a valid credential' );
update_option( 'service', array( 'password' => array( 'value' => 'separate-password' ) ) );
$options['service']['key'] = $options['service']['password'];
check( $api->get_secret( 'key', 'service' ) instanceof WP_Error, 'Ciphertext swapping across fields fails' );
$blog_id = 2;
check( $api->get_secret( 'password', 'service' ) instanceof WP_Error, 'Ciphertext swapping across sites fails' );
$blog_id = 1;
update_option( 'service', array( 'key' => array( 'delete' => '1' ) ) );
check( '' === $api->get_secret( 'key', 'service' ), 'Explicit deletion' );
check( 'separate-password' === $api->get_secret( 'password', 'service' ), 'Deletion leaves other credentials intact' );

// A deleted option triggers the update_option -> add_option double-sanitization path.
unset( $options['service'] );
update_option( 'service', array( 'key' => array( 'value' => $secret ) ) );
check( $secret === $api->get_secret( 'key', 'service' ), 'Repeated sanitization does not double-encrypt' );
$first = $options['service'];
update_option( 'service', $first );
check( $first === $options['service'], 'Existing ciphertext survives a normal options update' );
$options['service']['key'] = 'legacy-plaintext';
check( $api->get_secret( 'key', 'service' ) instanceof WP_Error, 'Legacy plaintext is never silently used' );
update_option( 'service', array( 'key' => array( 'value' => 'migrated-credential' ) ) );
check( 'migrated-credential' === $api->get_secret( 'key', 'service' ), 'Explicit replacement migrates legacy value' );
check( ! str_contains( implode( '\n', $errors ), $secret ), 'Errors do not expose credentials' );

// Exercise the default wp-config.php constant provider as well as the injected test provider.
define( 'WSA_SETTINGS_SECRET_KEY', $correct_key );
$default_cipher = new Secret_Cipher();
check( 'configured' === $default_cipher->decrypt( $default_cipher->encrypt( 'configured', 'default' ), 'default' ), 'Default provider reads configured global constant' );

// An unexpected provider exception must never leak its message into an admin notice.
$failing_api = new Settings_API( new Secret_Cipher( static function () use ( $secret ) {
    throw new RuntimeException( $secret );
} ) );
$failing_api->set_fields( array( 'isolated' => $fields ) );
register_setting( 'isolated', 'isolated', array( $failing_api, 'sanitize_options' ) );
update_option( 'isolated', array( 'key' => array( 'value' => 'replacement' ) ) );
check( str_contains( end( $errors ), 'Encryption failed.' ) && ! str_contains( end( $errors ), $secret ), 'Unknown exceptions use safe generic notice' );

echo "PASS: {$assertions} assertions (real upstream class; WordPress APIs stubbed).\n";
