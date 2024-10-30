<?php
/*
Plugin Name: Botnet Blocker
Plugin URI: http://wordpress.org/extend/plugins/botnet-blocker/
Description: Free botnet IP blocker according to public DNSBL bases. Based on public DNSBL class.
Author: Dennis Wallace
Version: 1.2.5
License: GPLv2 or later
*/

/*
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

if ( ! class_exists( "DNSBL" ) ) {
	include_once( 'DNSBL.php' ); 	// see http://xbsoft.org/php/
}

if ( ! class_exists( 'BNBlocker_Config' ) ) {
	include_once( 'class.bnblocker-config.php' );
}

if ( ! class_exists( 'BNBlocker_Admin' ) ) {
	include_once( 'class.bnblocker-admin.php' );
}


if ( ! class_exists( 'Plugin_BNBlocker' ) ) {
	/**
	 * Checks for a spammish IP at init time, and blocks/404s/handles it.
	 */
	class Plugin_BNBlocker {
		/**
		 * Activate the plugin
		 */
		public static function activate() {
		}
		
		/**
		 * Deactivate the plugin
		 */
		public static function deactivate() {
		}
		
		/**
		 * Uninstall the plugin
		 */
		public static function uninstall() {
		}
		/**
		 * Things that run during the WP init action
		 */
		public function handle_init() {
		  load_plugin_textdomain( 'botnet-blocker', false, 'botnet-blocker/languages' );
		}
		
		/**
		 * Things that run during the WP plugins loaded action
		 */
		public function handle_pre_get_posts( $query ) {
			if ( $this->config->onload != 'on' ) {
				// We only do this if the option is set
				return;
			}
            
            if ( ! $query->is_main_query() ) {
                return;
            }
	  		
			if ( $this->is_botnet() ) {
				$this->block( 404, $query );
			}
		}
		
		/**
		 * Initializes the new instance of this object
		 */
		public function __construct() {
			$this->config = new BNBlocker_Config();
			if ( isset( $_GET['debug'] ) ) {
				header('X-BotnetBlocker-Debug-Mode: Debug Mode Enabled');
				$this->config->debug = 'on';
			}
			
			
			// Add the current server address to the skiplist
			if( ! empty( $_SERVER['SERVER_ADDR'] ) ) {
				$this->skiplist[] = $_SERVER['SERVER_ADDR'];
			}
			
			add_action( 'init', array( &$this, 'handle_init' ) );
			add_action( 'pre_get_posts', array( &$this, 'handle_pre_get_posts' ), 0 );
		}
		
		/**
		 * Checks the current sessions's IP addresses for spammish ones
		 *
		 * @return bool True if a botnet address detected, False if not.
		 */
		public function is_botnet() {
			$this->timer_start();
			
			$ips = '';
			if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
				$ips = $_SERVER['HTTP_X_FORWARDED_FOR'];
			}
		    $ips .= "\n".$_SERVER['REMOTE_ADDR'];
			$ips = $this->config->preplist( $ips );
			
			$result = false;
			$whitelisted = false;
			$blacklisted = false;

			$skiplist = $this->config->skiplist();
			$blacklist = $this->config->blacklist();
			$whitelist = $this->config->whitelist();
			$blacklist_dns = $this->config->dns_blacklist();
			$whitelist_dns = $this->config->dns_whitelist();
			
			if ( $this->config->debug == 'on' ) {
				header('X-BotnetBlocker-Debug-0_IPList: '.implode(';',$ips));
				header('X-BotnetBlocker-Debug-1_CurrentIP: '.$_SERVER['REMOTE_ADDR']);
				header('X-BotnetBlocker-Debug-2_SkipList: '.implode(';',$skiplist));
				header('X-BotnetBlocker-Debug-3_Whitelist: '.implode(';',$whitelist));
				header('X-BotnetBlocker-Debug-4_Blacklist: '.implode(';',$blacklist));
				header('X-BotnetBlocker-Debug-5_DNSWhitelist: '.implode(';',$whitelist_dns));
				header('X-BotnetBlocker-Debug-6_DNSBlacklist: '.implode(';',$blacklist_dns));
			}
			
			// If we have nothing to do, skip the expensive checks.
			$all_lists = array_merge( $whitelist, $blacklist, $whitelist_dns, $blacklist_dns );
			if ( empty( $all_lists ) && ( $this->config->rbl == 'none' ) ) {
				return $result;
			}
			
			foreach ( $ips as $ip ) {
				if ( empty( $ip ) ) {
					continue;
				}
				
				if ( ! empty( $skiplist ) ) {
					if ( $this->netmatch_array( $ip, $skiplist ) ) {
						continue;
					}
				}
				
				if ( ! empty( $whitelist ) ) {
					if ( $this->netmatch_array( $ip, $whitelist ) ) {
						$whitelisted = true;
						continue;
					}
				}
						
				if ( ! empty( $blacklist ) ) {
					if ( $this->netmatch_array( $ip, $blacklist ) ) {
						$blacklisted = true;
						continue;
					}
				}
				
				if ( ! empty( $whitelist_dns ) || ! empty( $blacklist_dns ) ) {
					// We have something to match.  Check the DNS name
					$dns = @gethostbyaddr( $ip );
					if ( $this->config->debug == 'on' ) {
						header( 'X-BotnetBlocker-Debug-DNSLookup: ' . $dns );
					}
					if ( ( $dns !== false ) && ( $dns != $ip ) ) {
						// We have a DNS address for the IP.  Check it!
						if ( ! empty( $whitelist_dns ) ) {
							if ( $this->dnsmatch_array( $dns, $whitelist_dns ) ) {
								$whitelisted = true;
								continue;
							}
						}
						
						if ( ! empty( $blacklist_dns ) ) {
							if ( $this->dnsmatch_array( $dns, $blacklist_dns ) ) {
								$blacklisted = true;
								continue;
							}
						}
					}
				}
						
				if ( ( $whitelisted || $blacklisted || $result ) == false ) {
					// Only check for botnet membership if we've not already decided
					if ( $this->config->rbl != 'none' ) {
						if ( $this->config->dnsbl->CheckSpamIP( $ip ) ) {
							$result = true;
						}
					}
				}
			}
			
			$this->timer_stop();
			
			if ( $whitelisted ) {
				if ( $this->config->debug == 'on' ) {
					header('X-BotnetBlocker-Debug-Result: Whitelist');
				}
				return false;
			}
			
			if ( $blacklisted ) {
				if ( $this->config->debug == 'on' ) {
					header('X-BotnetBlocker-Debug-Result: Blacklist');
				}
				return true;
			}
			
			if ( $this->config->debug == 'on' ) {
				header('X-BotnetBlocker-Debug-Result: ' . ( $result ? 'Bot' : 'OK' ) );
			}
			return $result;
		}
		
		/**
		 * This is called when a spammish IP is detected.
         *
         * @param integer $status The status code to return.  Default is 404.
         * @param WP_Query $query The query object to set as a 404 result.  Null uses the main global $wp_query object if possible.  Default is null.
		 */
		public function block( $status = 404, $query = null ) {
			// We've got a blacklisted IP.  404 it.
			if( is_null( $query ) ) {
			    if( isset( $GLOBALS['wp_query'] ) ) {
			        $query = $GLOBALS['wp_query'];
			    }
			}
            if ( method_exists( $query, 'set_404' ) ) {
                $query->set_404();
            }
		    status_header( $status );
		    nocache_headers();
		}
		
		/**
		 * Returns whether the IP is within a given network/mask in CIDR format ( e.g. 192.168.0.0/16 )
		 *
		 * @param $ip string IP address to match
		 * @param $cidr string Netmask to match.  Must be in CIDR format.
		 *
		 * @return bool Whether the IP is within the mask.  True if a match occurs, false if not.
		 */
		public function netmatch( $ip, $cidr ) {
			if ( empty( $cidr ) || empty( $ip ) ) {
				return false;
			}
			
			$cidr .= '/32'; // Put the default mask in case one wasn't given.  We ignore it if it's extra.
			$parts = explode( '/', $cidr );
            $net = ip2long( $parts[0] );
			$mask = intval( $parts[1] );
            $mask = ( 1 << ( 32 - $mask ) ) - 1;
			$net = $net & ~( $mask ); // Enforce the mask on the network too (just in case)
    		return ( ( ip2long( $ip ) & ~( $mask ) ) == $net );
 		}
		
		/**
		 * Returns whether the IP is within a given array of network/masks in CIDR format ( e.g. 192.168.0.0/16 )
		 *
		 * @param $ip string IP address to match
		 * @param $arr array List of network/masks to match.  Each item must be in CIDR format.
		 *
		 * @return bool Whether the IP is within the array of network/masks.  True if a match occurs, false if not.
		 */
		public function netmatch_array( $ip, $arr ) {
			foreach ( $arr as $cidr ) {
				if ( $this->netmatch( $ip, $cidr ) ) {
					return true;
				}
			}
			
			return false;
		}
		
		private $timerstart = 0;
		private $timercount = 0;
		
		private function timer_start() {
			$this->timerstart = microtime( true );
		}
		
		private function timer_stop( $precision = 10 ) {
			$this->timercount++;
			$timeend = microtime( true );
			$timetotal = $timeend - $this->timerstart;
			if ( isset( $_GET['debug'] ) ) {
				$r = ( function_exists( 'number_format_i18n' ) ) ? number_format_i18n( $timetotal, $precision ) : number_format( $timetotal, $precision );
				header( 'X-BotnetBlocker-Timer-' . strval( $this->timercount ) . ': ' . $r );
			}
		}
		
		/**
		 * Returns whether the DNS name is within a given array of names
		 *
		 * @param $dns string DNS name to match
		 * @param $arr array List of names to match.
		 *
		 * @return bool Whether the DNS name is within the array of names.  True if a match occurs, false if not.
		 */
		private function dnsmatch_array( $dns, $arr ) {
			foreach ( $arr as $entry ) {
				if ( $this->dnsmatch( $dns, $entry ) ) {
					return true;
				}
			}
			
			return false;
		}
		
		/**
		 * Returns whether the DNS name matches a given name
		 *
		 * @param $dns string DNS name to match
		 * @param $name string Name to match.
		 *
		 * @return bool Whether the DNS name matches the name.  True if a match occurs, false if not.
		 */
		public function dnsmatch( $dns, $name ) {
			if ( empty( $name ) || empty( $dns ) ) {
				return false;
			}
			
			$match = strtolower( $dns );
			$len = strlen( $name );
			$match = substr( $match, -$len );
			return ( $match == $name );
 		}
		
	}
}

if ( class_exists( 'Plugin_BNBlocker' ) && class_exists( 'BNBlocker_Admin' ) && function_exists( 'register_activation_hook' ) ) {
    // Installation and uninstallation hooks
    register_activation_hook(__FILE__, array('Plugin_BNBlocker', 'activate'));
    register_deactivation_hook(__FILE__, array('Plugin_BNBlocker', 'deactivate'));
    register_uninstall_hook(__FILE__, array('Plugin_BNBlocker', 'uninstall'));

    // instantiate the plugin class
    global $wp_plugin_bnblocker;
	$wp_plugin_bnblocker = new Plugin_BNBlocker();
	$wp_plugin_bnblocker_admin = new BNBlocker_Admin();
}
