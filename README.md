# Yet Another LDAP CakePHP Plugin

CakePHP plugin for LDAP Authentication.

## Requirements

This Plugin has the following requirements:

* CakePHP 2.2.0 or greater.
* PHP 5.3.0 or greater.

**It could be work on lower versions of CakePHP or PHP**

## Installation

### 1. Set up your Auth environment

* Create your "users" table as specified in database scheme example. If you use Mysql basically is as it follows:
```sql
CREATE TABLE IF NOT EXISTS `groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
  `created` datetime DEFAULT NULL,
  `modified` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `password` char(40) COLLATE utf8_unicode_ci DEFAULT NULL,
  `group_id` int(11) NOT NULL,
  `created` datetime DEFAULT NULL,
  `modified` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB;
```
* This plugin is designed to work exactly as CakePHP default auth component. 

See: [CakePHP: Simple Authentication and Authorization Application](http://book.cakephp.org/2.0/en/tutorials-and-examples/blog-auth-example/auth.html)

### 2. Configure Auth in your AppController

This config is pretty much the same as CakePHP tutorials about Auth and ACL. It should look something like this:
```php
App::uses('Controller', 'Controller');

class AppController extends Controller {

	public $components = array(
		'Acl',
		'Auth' => array(
			'authorize' => array(
				'Actions' => array('actionPath' => 'controllers')
			)
		),
		'Session',
	);

	public $helpers = array('Html', 'Form','Session');

	public function beforeFilter() {
		//Configure AuthComponent
		$this->Auth->loginAction = array(
			'plugin' => false, 
			'controller' => 'users',
			'action' => 'login'
			);
		$this->Auth->logoutRedirect = array(
			'plugin' => false, 
			'controller' => 'users',
			'action' => 'login'
			);
		$this->Auth->loginRedirect = '/';

		$this->Auth->authError = __('You are not authorized to access that location.');

		// If YALP not loaded then use Form Auth
		if (CakePlugin::loaded('YALP'))
			$this->Auth->authenticate = array('YALP.LDAP' => null);
		
		parent::beforeFilter();
	}
}
```

### 3. Download YALP

* Clone/Copy the files in this directory into `app/Plugin/YALP`. This can be done with the git submodule command
```sh
git submodule add https://github.com/jvalecillos/cakephp-yalp.git app/Plugin/YALP
```

### 4. Configure the plugin

* Ensure the plugin is loaded in `app/Config/bootstrap.php`:
```php
CakePlugin::load('YALP', array('bootstrap' => true));
```
* Create a `app/Config/ldap.php` config file with correspondent LDAP values. E.g.:
```php
$config['LDAP']['server'] = 'ldap://com.example:3268/DC=example';
$config['LDAP']['port'] = '3268';
$config['LDAP']['user'] = 'DOMAIN\ldap_user';
$config['LDAP']['password'] = 'password';
// Base DN for searching under
$config['LDAP']['base_dn'] = 'OU=Employees,DC=com,DC=example';
// This is an LDAP filter that will be used to look up user objects by username.
// %USERNAME% will be replaced by the username entered by the user.
// Therefore, you can do things like proxyAddresses lookup to find
// a user by any of their email addresses.
$config['LDAP']['user_filter'] = "(&(objectClass=User) (sAMAccountName=%USERNAME%))";
$config['LDAP']['user_wide_filter'] = "(& (objectClass=User) (| (sAMAccountName=%USERNAME%*) (givenName=%USERNAME%*) (sn=%USERNAME%*) ) )";
// Form fields - we're expecting a username and password,
// but the form data might call them e.g. 'email' and 'password'
$config['LDAP']['form_fields'] = array ('username' => 'username', 'password' => 'password');
// LDAP fields to retrieve by default
$config['LDAP']['ldap_attribs'] = array ('samaccountname','givenname', 'sn', 'mail', 'department');
// Database model for users
$config['LDAP']['db_model'] = "User";
// LDAP filter to look up for group membership
$config['LDAP']['group_filter'] = "(&(objectCategory=User) (memberOf=CN=%GROUPNAME%, OU=Common Groups,". $config['LDAP']['base_dn'] ."))";
```
* You could change LDAP filters as your need. Below is a link about Active Directory particular case.
* Please notice that in this case username and samaccountname (ldap attribute) correspond each other and are use for authentication.

See: [Active Directory: LDAP Syntax Filters](https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx)

## Licence

MIT

[@jvalecillos]:http://twitter,com/jvalecillos
[web]:http://jvalecillos.net
