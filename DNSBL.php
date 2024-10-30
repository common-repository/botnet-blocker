<?php
///////////////////////////////////////////////////////////////////////////
//
//    DNSBL - Spam IP address checker.
//    Copyright (C) 2011 Alexey A.Znayev
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//    Alexey A.Znayev, znaeff@mail.ru, http://xbsoft.org, http://xbsoft.ru
//
///////////////////////////////////////////////////////////////////////////

// This file contains public class DNSBL

// This class performs IP address check in spam blocking lists as described
// on http://ru.wikipedia.org/wiki/RBL

if (!class_exists("DNSBL")) {
	class DNSBL {

		private $_aCheckers = array(// list of checkers available for individual checking
		'spamhaus_xbl' => array('.xbl.spamhaus.org', false), //not available for group checking with 'all' key
		'spamhaus' => array('.zen.spamhaus.org', true), //available for group checking with 'all' key
		'spamcop' => array('.bl.spamcop.net', true), //available for group checking with 'all' key
		'dsbl' => array('.list.dsbl.org', false), //not available for group checking with 'all' key
		'ordb' => array('.relays.ordb.org', false), //not available for group checking with 'all' key
		'sorbs' => array('.dnsbl.sorbs.net', false), //not available for group checking with 'all' key
		'njabl' => array('.dnsbl.njabl.org', false)	//not available for group checking with 'all' key
		);
		// AZ - 1. Key 'all' is illegal
		// AZ - 2. Most of spammer IP addresses is covered by 'spamhaus' & 'spamcop' (and they are fast),
		//         some of the rest may not work sometimes, you can make them group checking available after individual testing

		private $_sDefaultChecker = 'spamhaus_xbl';

		///////////////////////////////////////////////////////////////////////////
		// CheckSpamIP - check IP for spam in checkers : given, default or all available for group checking (may be slow)
		// parameters:
		// string $ip - ip address
		// string $checker - checker name or 'all' or nothing
		// returns:
		// true when IP exitsts in spam-lists of $checker or at least one of all checkers
		// false when not or when ip address is local or not correct
		public function CheckSpamIP($ip, $checker = '') {
			if (empty($ip))
				return false;
			if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $ip) != 1)
				return false;
			$octets = explode('.', $ip);
			if ($octets[0] == '127')
				return false;
			if ($octets[0] == '10')
				return false;
			if ($octets[0] == '192' && $octets[0] == '168')
				return false;
			if ($octets[0] == '169' && $octets[0] == '254')
				return false;
			// ms windows
			if ((int)$octets[0] > 255 || (int)$octets[1] > 255 || (int)$octets[2] > 255 || (int)$octets[3] > 255)
				return false;
			$ret_val = false;
			$PTR = implode(array_reverse($octets), '.');
			if ($checker === 'all') {
				foreach (array_values($this->_aCheckers) as $c) {
					if ($c[1]) {
						$ret_val = $ret_val || $this -> _CheckDNSAnswer(dns_get_record($PTR . $c[0], DNS_A));
					}
					if ($ret_val)
						break;
				}
			} else if (array_key_exists($checker, $this -> _aCheckers)) {
				$ret_val = $this -> _CheckDNSAnswer(dns_get_record($PTR . $this -> _aCheckers[$checker][0], DNS_A));
			} else {
				$ret_val = $this -> _CheckDNSAnswer(dns_get_record($PTR . $this -> _aCheckers[$this -> _sDefaultChecker][0], DNS_A));
			}
			return $ret_val;
		}

		///////////////////////////////////////////////////////////////////////////
		// GetCheckers - gets list of available checker names
		// returns:
		// array of strings
		public function GetCheckers() {
			return array_keys($this -> _aCheckers);
		}

		///////////////////////////////////////////////////////////////////////////
		// GetGroupCheckers - gets list of checker names available for group checking with 'all' key
		// returns:
		// array of strings
		public function GetGroupCheckers() {
			$ret_val = array();
			foreach (array_keys($this->_aCheckers) as $k)
				if ($this -> _aCheckers[$k][1])
					array_push($ret_val, $k);
			return $ret_val;
		}

		///////////////////////////////////////////////////////////////////////////
		// GetDefaultChecker - gets default checker name
		// returns:
		// string
		public function GetDefaultChecker() {
			return $this -> _sDefaultChecker;
		}

		///////////////////////////////////////////////////////////////////////////
		// SetDefaultChecker - sets default checker name
		// parameters:
		// string $new_checker - new default checker name
		// returns:
		// true when success
		// false when failed ($new_checker is not in the list of available checker names)
		public function SetDefaultChecker($new_checker) {
			if (array_key_exists($new_checker, $this -> _aCheckers)) {
				$this -> _sDefaultChecker = $new_checker;
				return true;
			} else {
				return false;
			}
		}

		///////////////////////////////////////////////////////////////////////////
		// EnableGroupChecking - sets checker available for group checking
		// parameters:
		// string $checker - checker name
		// returns:
		// true when success ($checker is included)
		// false when failed ($checker is not in the list of available checker names)
		public function EnableGroupChecking($checker) {
			if (array_key_exists($checker, $this -> _aCheckers)) {
				$this -> _aCheckers[$checker][1] = true;
				return true;
			} else {
				return false;
			}
		}

		///////////////////////////////////////////////////////////////////////////
		// DisableGroupChecking - sets checker not available for group checking
		// parameters:
		// string $checker - checker name
		// returns:
		// true when success ($checker is excluded)
		// false when failed ($checker is not in the list of available checker names)
		public function DisableGroupChecking($checker) {
			if (array_key_exists($checker, $this -> _aCheckers)) {
				$this -> _aCheckers[$checker][1] = false;
				return true;
			} else {
				return false;
			}
		}

		// private methods

		///////////////////////////////////////////////////////////////////////////
		// _CheckDNSAnswer - checks DNS-server answer for 127.0.0.* values
		// returns:
		// true when success
		// false when failed
		private function _CheckDNSAnswer($dns_answer) {
			if (!is_array($dns_answer))
				return false;
			$len = count($dns_answer);
			if ($len <= 0)
				return false;
			for ($i = 0; $i < $len; $i++) {
				$obj = $dns_answer[$i];
				if (!(is_object($obj) || is_array($obj)))
					return false;
				$ip_str = $obj['ip'];
				if (!is_string($ip_str))
					return false;
				$pos = strpos($ip_str, '127.0.0.');
				if ($pos !== false)
					return true;
			}
			return false;
		}

	} // end of class DNSBL

}
