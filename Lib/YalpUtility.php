<?php
/**
 * Yet Another LDAP Plugin
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright Copyright 2013, Jose Valecillos.
 * @link http://jvalecillos.net
 * @author Jose Valecillos <valecillosjg@gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.php The MIT License
 */
class YalpUtility extends Object {
	var $server;
	var $port;
	var $user;
	var $password;
	var $base_dn;
	var $user_filter;
	var $group_filter;
	var $ldap_attribs;
	//var $default;

/**
 * Constructor
 *
 * @param array $settings Array of settings to use.
 */
	
	function __construct($settings = array()) {

		$this->server = Configure::read('LDAP.server');
		$this->server = (isset($settings['server'])) ? $settings['server'] : $this->server;

		$this->port = Configure::read('LDAP.port');
		$this->port = (isset($settings['port'])) ? $settings['port'] : $this->port;

		$this->user = Configure::read('LDAP.user');
		$this->user = (isset($settings['user'])) ? $settings['user'] : $this->user;

		$this->password = Configure::read('LDAP.password');
		$this->password = (isset($settings['password'])) ? $settings['password'] : $this->password;

		$this->base_dn = Configure::read('LDAP.base_dn');
		$this->base_dn = (isset($settings['base_dn'])) ? $settings['base_dn'] : $this->base_dn;

		$this->user_filter = Configure::read('LDAP.user_filter');
		$this->user_filter = (isset($settings['user_filter'])) ? $settings['user_filter'] : $this->user_filter;

		$this->user_wide_filter = Configure::read('LDAP.user_wide_filter');
		$this->user_wide_filter = (isset($settings['user_wide_filter'])) ? $settings['user_wide_filter'] : $this->user_wide_filter;

		$this->group_filter = Configure::read('LDAP.group_filter');
		$this->group_filter = (isset($settings['group_filter'])) ? $settings['group_filter'] : $this->group_filter;

		$this->ldap_attribs = Configure::read('LDAP.ldap_attribs');
		$this->ldap_attribs = (isset($settings['ldap_attribs'])) ? $settings['ldap_attribs'] : $this->ldap_attribs;

		//$model = Configure::read('LDAP.db_model');
		//$settings['userModel'] = (isset($settings['userModel'])) ? $settings['userModel'] : $model;
		//$this->model = ClassRegistry::init($model);

		parent::__construct();
	}

/**
 * Helper function to connect to the LDAP server
 * Looks at the plugin's settings to get the LDAP connection details
 * @throws CakeException
 * @return LDAP connection as per ldap_connect()
 */
	
	private function __ldapConnect() {

		$ldapConnection = @ldap_connect($this->server, $this->port);

		//these next two lines are required for windows server 03
		ldap_set_option($ldapConnection, LDAP_OPT_REFERRALS, 0);
		ldap_set_option($ldapConnection, LDAP_OPT_PROTOCOL_VERSION, 3);

		if (!$ldapConnection) {
			throw new CakeException("Could not connect to LDAP authentication server");
		}

		$bind = @ldap_bind($ldapConnection, $this->user, $this->password);

		if (!$bind) {
			throw new CakeException("Could not bind to LDAP authentication server - check your bind DN and password");
		}

		return $ldapConnection;
	}

/**
 * Helper function to find a user on the LDAP server and validate his credentials
 * Looks at the plugin's settings to get the LDAP connection details
 * @param string $username The username/identifier
 * @param string $password The password
 * @return boolean TRUE on success or FALSE on failure.
 */

	public function validateUser($username, $password)
	{
		// Get the user_filter setting and insert the username
		$this->user_filter = preg_replace('/%USERNAME%/', $username, $this->user_filter);

		// Connect to LDAP server and search for the user object
		$ldapConnection = $this->__ldapConnect();

		// Suppress warning when no object found
		$results = @ldap_search($ldapConnection, $this->base_dn, $this->user_filter, $this->ldap_attribs, 0, 1);

		// Failed to find user details, not authenticated.
		if (!$results || ldap_count_entries($ldapConnection, $results) == 0) {
			CakeLog::write('yalp', "[YALPUtility->validateUser] Could not find user '$username' on LDAP");
			return false;
		}

		// Got multiple results, sysadmin did something wrong!
		if (ldap_count_entries($ldapConnection, $results) > 1) {
			///	$this->log("[YALP.authenticate] Multiple LDAP results for $username", 'ldapauth');
			return false;
		}

		// Found the user! Get their details
		$ldapUser = ldap_get_entries($ldapConnection, $results);

		$ldapUser = $ldapUser[0];

		// Now try to re-bind as that user
		$bind = @ldap_bind($ldapConnection, $ldapUser['dn'], $password);

		// If the password didn't work, bomb out
		return $bind;
	}

	public function getUsers($ldapGroup = NULL, $ldapUser = NULL, $attributes = NULL, $sizelimit = 1000) {
		// Add filter by group if avaible
		$this->group_filter = preg_replace('/%GROUPNAME%/', $ldapGroup, $this->group_filter);
		$filter = $this->group_filter;

		// Add filter by user if avaible
		if (isset($ldapUser) && !empty($ldapUser))
		{
			$this->user_wide_filter = preg_replace('/%USERNAME%/', $ldapUser, $this->user_wide_filter);
			$filter = '(& ' . $this->group_filter . $this->user_wide_filter . ' )';
		}

		// Override ldap attributes to get if avaible
		$attributes = (isset($attributes)) ? $attributes : $this->ldap_attribs;

		// Connect to LDAP server and search for the user object
		$ldapConnection = $this->__ldapConnect();

		// Suppress warning when no object found
		$results = ldap_search($ldapConnection, $this->base_dn, $filter, $attributes, 0, $sizelimit);

		// Failed to find users details, not authenticated.
		if (!$results || ldap_count_entries($ldapConnection, $results) < 1) {
			CakeLog::write('yalp', "[YALPUtility->getUsers] Could not find users with selected criteria");
			return false;
		}

		// Found the users! Get theirs details
		$ldapUsers = ldap_get_entries($ldapConnection, $results);
		// Parse array
		$ldapUsers = $this->_parseLDAPArray($ldapUsers);

		return $ldapUsers;
	}

	private function _parseLDAPArray($data)
	{
		if (isset($data) && !empty($data)) {
			$result = array();
			// Total of LDAP records
			$countTotal = $data['count'];
			for ($x = 0; $x < $countTotal; $x++) {
				// Total of fields per record
				$countFields = $data[$x]['count'];
				for ($y = 0; $y < $countFields; $y++) {
					// Name of field
					$field = $data[$x][$y];
					// Get the value of the field
					$result[$x][$field] = (isset($data[$x][$field][0])) ? $data[$x][$field][0] : null;
				}
			}
			return $result;
		}
	}

/**
 * Replace specials characters by simple equivalents
 * @param $string
 *  string to clean up
 * @return $string
 *  string cleaned up string
 */
	function replace_specials_characters($s) {
			//$s = mb_convert_encoding($s, 'UTF-8','');
			$s = preg_replace("/á|à|â|ã|ª/","a",$s);
			$s = preg_replace("/Á|À|Â|Ã/","A",$s);
			$s = preg_replace("/é|è|ê/","e",$s);
			$s = preg_replace("/É|È|Ê/","E",$s);
			$s = preg_replace("/í|ì|î/","i",$s);
			$s = preg_replace("/Í|Ì|Î/","I",$s);
			$s = preg_replace("/ó|ò|ô|õ|º/","o",$s);
			$s = preg_replace("/Ó|Ò|Ô|Õ/","O",$s);
			$s = preg_replace("/ú|ù|û/","u",$s);
			$s = preg_replace("/Ú|Ù|Û/","U",$s);
			$s = str_replace(array("ñ", "Ñ"), array("n", "N"), $s);
			$s = str_replace(array('ç', 'Ç'), array('c', 'C'), $s);

			//$s = str_replace(" ","_",$s);
			//$s = preg_replace('/[^a-zA-Z0-9_\.-]/', '', $s);
			return $s;
		}

}