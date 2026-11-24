# Secure fields for WeDevs_Settings_API

A reusable subclass adding `type => 'secret'` for API keys, SMTP passwords, and other credentials that a plugin must recover to contact an external service. The upstream `password` field masks the input visually but fills its HTML value with the saved credential. This extension renders an empty input and stores authenticated ciphertext.

Requires WordPress 6.6+, PHP 8.1+, PHP Sodium, and the original [WeDevs_Settings_API](https://github.com/tareq1988/wordpress-settings-api-class). This is a library extension, not a standalone installable plugin. Load it after the parent class in your plugin. Existing `password` fields retain their original behavior; opt in with `secret`.

## Setup

Generate a key once on a trusted machine:

```sh
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
```

Keep it outside the database and repository, for example in your hosting environment. In `wp-config.php`, before WordPress loads:

```php
define( 'WSA_SETTINGS_SECRET_KEY', getenv( 'WSA_SETTINGS_SECRET_KEY' ) ?: '' );
```

Use a dedicated random key. Do not derive it from WordPress authentication salts, and do not regenerate it on each request. Back it up separately: losing or changing it makes saved credentials unreadable. Key rotation requires decrypting with the old key and re-encrypting with the new one, or replacing every credential. Automated rotation is not included.

Load your existing parent class and then this extension:

```php
require_once __DIR__ . '/path/to/class.settings-api.php';
require_once __DIR__ . '/path/to/WeDevs_Settings/src/Settings_API.php';

$settings = new \WeDevsSecureSettings\Settings_API();
$settings->set_sections( array(
    array( 'id' => 'my_service', 'title' => 'Service' ),
) );
$settings->set_fields( array(
    'my_service' => array(
        array( 'name' => 'api_key', 'label' => 'API key', 'type' => 'secret' ),
    ),
) );
add_action( 'admin_init', array( $settings, 'admin_init' ) );
```

Configure the fields on all requests where you need to retrieve credentials. Call `admin_init()` only on the admin hook. Use the normal parent settings forms (`show_forms()`) in a capability-protected admin page; they supply WordPress nonces and submit to `options.php`. See [the complete settings-page example](examples/integration.php).

Read credentials explicitly in server-side code:

```php
$key = $settings->get_secret( 'api_key', 'my_service' );
if ( is_wp_error( $key ) || '' === $key ) {
    // Stop the service request and report an unavailable credential without logging it.
    return;
}
// Use $key in an HTTPS request's authentication header.
```

`get_option()` still returns ciphertext. `get_secret()` returns the decrypted string, an empty string when unset, or `WP_Error` for a missing/wrong key, corrupted data, or an unregistered field. It intentionally has no user capability check so trusted PHP can use credentials in cron and frontend service calls. Never expose its result through HTML, JavaScript, REST, URLs, or logs.

## Saving behavior

- Blank or omitted secret fields keep the existing value without re-encrypting it.
- A new value replaces the credential; spaces, quotes, backslashes, and percent sequences are preserved. The limit is 4096 bytes. Secret fields do not run `sanitize_text_field()` or custom field sanitizers, which could alter credentials.
- Checking **Delete saved credential** clears it. Submitting deletion and a nonempty replacement together produces an error and keeps the old value.
- Invalid input or encryption failure keeps the old value and adds a generic settings error. Display `settings_errors()` on the page.
- Sodium uses XChaCha20-Poly1305 with a fresh random nonce. The authenticated context binds the ciphertext to its site ID, section, and field name. Renaming fields or moving values to another multisite blog requires decrypting and re-encrypting them.
- Sections containing secrets have option autoload disabled. Settings are not registered for REST exposure; do not enable REST exposure for these option arrays elsewhere.
- The sanitizer checks the settings group's capability (normally `manage_options`). WordPress `options.php` checks the form nonce. Custom save endpoints must also check their own nonce. Programmatic writes require the appropriate current user and registered settings callbacks; direct database writes bypass this library.
- Ordinary field sanitizers are resolved within their section. Omitted fields retain their old values; unknown submitted fields are ignored. Normal field sanitizers should be idempotent because WordPress can invoke them twice.

For an authorized programmatic update after settings registration:

```php
$options = get_option( 'my_service', array() );
$options['api_key'] = array( 'value' => $new_key );
update_option( 'my_service', $options );
```

## Existing passwords and security limits

Changing a field from `password` to `secret` does **not** automatically migrate old plaintext. Re-enter and save the credential (preferably rotate it at its provider). The reader rejects legacy plaintext. Blank submissions preserve existing data, including legacy data. Old backups can still contain the plaintext.

This protects database-only leaks when the encryption key is stored separately. A compromised PHP process or plugin can access the key and decrypt credentials. Use HTTPS for admin pages and provider requests. The library cannot prevent other plugins from logging incoming settings requests. Password manager autofill is discouraged with `autocomplete="new-password"`, but browser behavior varies.

For passwords your application only needs to verify, use password hashing rather than recoverable encryption. WordPress user login passwords should use WordPress's user/password APIs.

## Tests

The regression suite runs against the real upstream parent class, with lightweight stubs for WordPress APIs. It covers encryption, tampering, field/site binding, rendering, replacement/deletion, malformed input, capabilities, failed saves, ordinary fields, and repeated sanitization.

```sh
php tests/run.php /path/to/upstream/class.settings-api.php
```

Validated in this workspace with PHP 8.4.27: all 46 assertions passed and all PHP files passed syntax checks. Disabling Sodium's encryption function also confirmed that encryption fails closed. PHP 8.1 compatibility is based on the language features used; that runtime was not available for execution here.

The harness is not a full WordPress integration or browser test. Before deploying, verify the settings page on a staging site: save, reload, leave blank, replace, delete, and submit an expired nonce or as an unauthorized user. Confirm database values are ciphertext, secrets are absent from page source, and the service client works. Also verify missing-key behavior and an existing plaintext field's replacement.

References: [upstream source](https://github.com/tareq1988/wordpress-settings-api-class/blob/master/src/class.settings-api.php), [WordPress Settings API](https://developer.wordpress.org/plugins/settings/settings-api/), [PHP Sodium encryption](https://www.php.net/manual/en/function.sodium-crypto-aead-xchacha20poly1305-ietf-encrypt.php).
