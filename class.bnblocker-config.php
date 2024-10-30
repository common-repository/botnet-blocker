<?php
/**
 * Plugin Configuration File
 *
 * All custom configuration is done here.
 */

if(!class_exists('BNBlocker_Config')) {
 	
	/**
	 * The configuration settings for the Botnet Blocker plugin.
	 */
	class BNBlocker_Config {
		/**
		 * The instance of a DNSBL object to use during lookups
		 */
		public $dnsbl = null;
		
		/**
		 * Whether or not to block during the plugins_loaded event.
		 */
		public $onload = '';

		/**
		 * The black list to check.
		 */
		public $rbl = '';

		/**
		 * Whether the plugin is in debug mode (exports timer and variable data to HTTP headers)
		 */
		public $debug = '';
		
		/**
		 * Whether or not to add the current server IP Address to
		 * the skiplist.
		 */
	  	public $skipself = 'on';
	   
		/**
		 * The text version of the skip list.
		 */
		public $skip = '127.0.0.1';
		
		/**
		 * The text version of the blacklist.
		 */
		public $black = '';
		
		/**
		 * The text version of the whitelist.
		 */
		public $white = '';
		
		/**
		 * The text version of the blacklist for DNS entries.
		 */
		public $black_dns = '';
		
		/**
		 * The text version of the whitelist for DNS entries.
		 */
		public $white_dns = '';
		
		/**
		 * Returns an array that will be used for the skip list.
		 * 
		 * @return array The list of network/masks that should be skipped.
		 */
		public function skiplist() {
			$a = '';
			if( $this->skipself == 'on' ) {
				if( ! empty( $_SERVER['SERVER_ADDR'] ) ) {
					$a = ';'.$_SERVER['SERVER_ADDR'];
				}
			}
			
			$array = $this->preplist( $this->skip . $a );
			return $array;
		}
		
		/**
		 * An array of addresses that will be reported as bots (as long as 
		 * they're not on the whitelist also).  
		 * 
		 * @return array The list of network/masks that should be blacklisted.
		 */
		public function blacklist() {
			$array = $this->preplist( $this->black );
			return $array;
		}
		
		/**
		 * An array of addresses that will be granted access no matter what.  
		 * Use with care - overrides blacklist and botnet membership checks.
		 * 
		 * @return array The list of network/masks that should be granted access.
		 */
		public function whitelist() {
			$array = $this->preplist( $this->white );
			return $array;
		}
		
		/**
		 * An array of DNS names that will be reported as bots (as long as 
		 * they're not on the whitelist also).  
		 * 
		 * @return array The list of DNS names that should be blacklisted.
		 */
		public function dns_blacklist() {
			$array = $this->preplist( $this->black_dns, false );
			return $array;
		}
		
		/**
		 * An array of DNS names that will be granted access no matter what.  
		 * Use with care - overrides blacklist and botnet membership checks.
		 * 
		 * @return array The list of DNS names that should be granted access.
		 */
		public function dns_whitelist() {
			$array = $this->preplist( $this->white_dns, false );
			return $array;
		}
		
		/**
		 * Performs manipulation to turn a string into an array of IPs
		 * 
		 * @param string $list The string to transform
		 * @param bool $ip Whether or not to return only an IPv4 address.  True strips all 
		 * non-conforming characters, False leaves everything intact.
		 * 
		 * @return array The string transformed into an array
		 */
		public function preplist( $list, $ip = true ) {
			$a = $list;
			$a = str_replace( array("\r", "\n"), "\n", $a );
			if ( $ip ) {
				$a = preg_replace( '/[^.0-9\/]+/', "\n", $list );
			} else {
				$a = strtolower( $a );
			}
			$a = trim( $a );
			$a = explode( "\n", $a );
			$b = array();
			foreach ( $a as $i ) {
				if ( ! empty ( $i ) ) {
					$n = strpos( $i, "#" );
					if ( $n !== false ) {
						$i = substr( $i, 0, $n - 1 );
					}
					$b[$i] = true;
				}
			}
			$array = array_keys( $b );
			if ( empty( $array ) ) {
				$array = array();
			}
			return $array;
		}
		
		/**
		 * Initialize all settings and load from WP (if available)
		 */
		public function __construct() {
			// Get the checked options
			$this->skipself = $this->get_option( 'bnblocker_skipself', 'bnblocker_core', 'on' );
			$this->onload = $this->get_option( 'bnblocker_onload', 'bnblocker_core', '' );
			
			// Get the skip list
			$this->skip = $this->get_option( 'bnblocker_skiplist', 'bnblocker_core', '127.0.0.1' );
			$this->white = $this->get_option( 'bnblocker_whitelist', 'bnblocker_core', '' );
			$this->black = $this->get_option( 'bnblocker_blacklist', 'bnblocker_core', '' );
			$this->white_dns = $this->get_option( 'bnblocker_whitelistdns', 'bnblocker_core', '' );
			$this->black_dns = $this->get_option( 'bnblocker_blacklistdns', 'bnblocker_core', '' );
			
			$this->dnsbl = new DNSBL();
			$this->rbl = $this->get_option( 'bnblocker_rbl', 'bnblocker_core', 'none' );
			if( $this->rbl != 'none' ) {
				$this->dnsbl->SetDefaultChecker( $this->rbl );
			}
		}
		
		/**
		 * Returns a keyed array of the Realtime Blacklists that are available in the plugin.
		 */
		public function get_rbl_list() {
			$array = array( 
				'none' => __( 'Ignore all RBLs', 'botnet-blocker' ),
				'all' => __( 'All valid blacklists', 'botnet-blocker' ),
			);
			foreach ( $this->dnsbl->GetCheckers() as $b ) {
				$array[$b] =  __( $b, 'botnet-blocker' );
			}
			return $array;
		}
		
		/**
		 * Gets the option value from the database
		 */
		private function get_option( $option, $section, $default = '' ) {
			if ( !function_exists( 'get_option' ) ) {
				return $default;
			}
			
	        $options = get_option( $section );
	
	        if ( isset( $options[$option] ) ) {
	            return $options[$option];
	        }
	
	        return $default;
	    }
	}
}
