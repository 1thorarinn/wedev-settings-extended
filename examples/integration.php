<?php
/**
 * Include this from your plugin after loading the original WeDevs_Settings_API.
 * This example adds Settings > Service credentials.
 */

require_once dirname( __DIR__ ) . '/src/Settings_API.php';

function wsa_demo_settings(): \WeDevsSecureSettings\Settings_API {
    static $settings;
    if ( null === $settings ) {
        $settings = new \WeDevsSecureSettings\Settings_API();
        $settings->set_sections( array(
            array( 'id' => 'wsa_demo_service', 'title' => 'Service credentials' ),
        ) );
        // Configure fields on frontend/cron requests too, so get_secret() can identify them.
        $settings->set_fields( array(
            'wsa_demo_service' => array(
                array(
                    'name' => 'api_key',
                    'label' => 'API key',
                    'type' => 'secret',
                    'desc' => 'Enter a new key to replace the saved credential.',
                ),
                array(
                    'name' => 'account_name',
                    'label' => 'Account name',
                    'type' => 'text',
                    'sanitize_callback' => 'sanitize_text_field',
                ),
            ),
        ) );
    }
    return $settings;
}

add_action( 'admin_init', array( wsa_demo_settings(), 'admin_init' ) );
add_action( 'admin_menu', static function () {
    add_options_page( 'Service credentials', 'Service credentials', 'manage_options', 'wsa-demo-service', static function () {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        echo '<div class="wrap"><h1>Service credentials</h1>';
        settings_errors( 'wsa_demo_service' );
        wsa_demo_settings()->show_navigation();
        // Parent forms supply settings_fields() nonces and submit to WordPress options.php.
        wsa_demo_settings()->show_forms();
        echo '</div>';
    } );
} );

// In your server-side service client:
// $key = wsa_demo_settings()->get_secret( 'api_key', 'wsa_demo_service' );
// if ( is_wp_error( $key ) || '' === $key ) { /* Stop: no usable credential. */ }
// Otherwise use $key in the provider's authentication header over HTTPS.
// Do not print it, log it, include it in a URL, or send it to browser JavaScript.
