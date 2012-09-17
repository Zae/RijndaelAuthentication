<?php

App::uses('Component', 'Controller/Component');
App::uses('RijndaelAuthenticate', 'RijndaelAuthentication.Controller/Component/Auth');

class RijndaelComponent extends Component {

	public function __construct(ComponentCollection $collection, $settings) {		
		parent::__construct($collection, $settings);
	}

	/**
	 * Create an encrypted password based on the username and plain-text password of a user.
	 *
	 * @param string $username
	 * @param string $password
	 * @return array(pass=>'', iv=>'')
	 * @uses RijndaelAuthenticate::createEncryptedPassword
	 */
	public function createEncryptedPassword($username, $password) {
		return RijndaelAuthenticate::createEncryptedPassword($username, $password);
	}
}

?>