<?php

if(!class_exists('BNBlocker_Config')) {
	include_once('class.bnblocker-config.php');
}

if(!class_exists('WeDevs_Settings_API')) {
	include_once('class.settings-api.php');
}

/**
 * WS Report Admin screens
 */
if ( !class_exists('BNBlocker_Admin' ) ) {
	class BNBlocker_Admin {
	
	    private $settings_api;
	    private $config;
	
	    function __construct() {
	        $this->settings_api = new WeDevs_Settings_API;
			$this->config = new BNBlocker_Config();

	        add_action( 'admin_init', array($this, 'admin_init') );
	        add_action( 'admin_menu', array($this, 'admin_menu') );
	    }
	
	    function admin_init() {
	
	        //set the settings
	        $this->settings_api->set_sections( $this->get_settings_sections() );
	        $this->settings_api->set_fields( $this->get_settings_fields() );
	
	        //initialize settings
	        $this->settings_api->admin_init();
	    }
	
	    function admin_menu() {
	        add_options_page( __('Botnet Blocker Settings', 'botnet-blocker'), __('Botnet Blocker', 'botnet-blocker'), 'delete_posts', 'bnblocker_settings', array($this, 'plugin_page') );
	    }

	    function get_settings_sections() {
	        $sections = array(
	            array(
	                'id' => 'bnblocker_core',
	                'title' => __( 'Settings', 'botnet-blocker' )
	            )
	        );
	        return $sections;
	    }
	
	    /**
	     * Returns all the settings fields
	     *
	     * @return array settings fields
	     */
	    function get_settings_fields() {
			
	        $settings_fields = array(
	            'bnblocker_core' => array(
	                array(
	                    'name'  			=> 'bnblocker_onload',
	                    'label' 			=> __( 'Block on Page Load', 'botnet-blocker' ),
	                    'desc'  			=> __( 'Redirects detected bots to a 404 page on page load.  Make sure your IP address is in the whitelist before activating (just in case)!', 'botnet-blocker' ),
	                    'type'  			=> 'checkbox',
	                    'default'			=> ''
	                ),
	                array(
	                    'name'  			=> 'bnblocker_rbl',
	                    'label' 			=> __( 'Realtime Blacklist Service', 'botnet-blocker' ),
	                    'desc'  			=> __( 'Which RBL service to use when checking for botnet addresses.', 'botnet-blocker' ),
	                    'type'  			=> 'select',
	                    'options'           => $this->config->get_rbl_list(),
	                    'default'			=> 'none'
	                ),
	                array(
	                    'name'  			=> 'bnblocker_skiplist',
	                    'label' 			=> __( 'Skip List', 'botnet-blocker' ),
	                    'desc'  			=> __( 'A list of IP addresses and/or network/mask combinations to skip checking.  Network/mask entries must be in CIDR form ( e.g., 192.168.0.0/16 ).', 'botnet-blocker' ),
	                    'type'  			=> 'textarea',
	                    'default'           => '127.0.0.1'
	                ),
	                array(
	                    'name'              => 'bnblocker_skipself',
	                    'label'             => __( 'Skip Self', 'botnet-blocker' ),
	                    'desc'              => __( 'If checked, the local server address will be added to the skip list.', 'botnet-blocker' ),
	                    'type'              => 'checkbox',
	                    'default'           => 'on'
	                ),
	                array(
	                    'name'  			=> 'bnblocker_whitelist',
	                    'label' 			=> __( 'Whitelist', 'botnet-blocker' ),
	                    'desc'  			=> __( 'A list of IP addresses and/or network/mask combinations to never mark as a bot.  The whitelist overrides the black list - if the same address is in both lists then it will be allowed.  Network/mask entries must be in CIDR form ( e.g., 192.168.0.0/16 ).', 'botnet-blocker' ),
	                    'type'  			=> 'textarea'
	                ),
	                array(
	                    'name'  			=> 'bnblocker_blacklist',
	                    'label' 			=> __( 'Blacklist', 'botnet-blocker' ),
	                    'desc'  			=> __( 'A list of IP addresses and/or network/mask combinations to always mark as a bot (unless also present on the white list).  Network/mask entries must be in CIDR form ( e.g., 192.168.0.0/16 ).', 'botnet-blocker' ),
	                    'type'  			=> 'textarea'
	                ),
	                array(
	                    'name'  			=> 'bnblocker_whitelistdns',
	                    'label' 			=> __( 'DNS Whitelist', 'botnet-blocker' ),
	                    'desc'  			=> __( 'A list of DNS names to never mark as a bot.  The whitelist overrides the black lists - if the same name is in both lists then it will be allowed.', 'botnet-blocker' ),
	                    'type'  			=> 'textarea'
	                ),
	                array(
	                    'name'  			=> 'bnblocker_blacklistdns',
	                    'label' 			=> __( 'DNS Blacklist', 'botnet-blocker' ),
	                    'desc'  			=> __( 'A list of DNS names to always mark as a bot (unless also present on the white list).', 'botnet-blocker' ),
	                    'type'  			=> 'textarea'
	                ),
	            )
	        );
	
	        return $settings_fields;
	    }
	
	    function plugin_page() {
	        echo '<div class="wrap">';
	
	        $this->settings_api->show_navigation();
	        $this->settings_api->show_forms();
	
	        echo '</div>';
	    }
	
	    /**
	     * Get all the pages
	     *
	     * @return array page names with key value pairs
	     */
	    function get_pages() {
	        $pages = get_pages();
	        $pages_options = array();
	        if ( $pages ) {
	            foreach ($pages as $page) {
	                $pages_options[$page->ID] = $page->post_title;
	            }
	        }
	
	        return $pages_options;
	    }
	
	}
}