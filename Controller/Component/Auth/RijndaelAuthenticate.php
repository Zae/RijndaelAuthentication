<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class RijndaelAuthenticate extends BaseAuthenticate {
	
	protected static $SALT;

	public function __construct(ComponentCollection $collection, $settings) {
		self::_getCakeSalt();
		
		parent::__construct($collection, $settings);
	}

	public function authenticate(CakeRequest $request, CakeResponse $response) {
		$user = $this->_findUser($request->data[$this->settings['userModel']]['email']);
		
		if($this->_decryptPWString($request->data[$this->settings['userModel']]['email'], $request->data[$this->settings['userModel']]['password'], $user['password'])){
			return $user;
		}
		return false;
	}

	/**
	* Find a user record using the username.
	*
	* @param string $username The username/identifier.
	* @param string $password null, not used, only available because of PHP strict method signature requirements.
	* @return Mixed Either false on failure, or an array of user data.
	*/
	protected function _findUser($username, $password = null) {
		$userModel = $this->settings['userModel'];
		list($plugin, $model) = pluginSplit($userModel);
		$fields = $this->settings['fields'];

		$conditions = array(
			$model . '.' . $fields['username'] => $username
		);
		if (!empty($this->settings['scope'])) {
			$conditions = array_merge($conditions, $this->settings['scope']);
		}

		$result = ClassRegistry::init($userModel)->find('first', array(
			'conditions' => $conditions,
			'recursive' => (int)$this->settings['recursive'],
			'contain' => $this->settings['contain'],
		));
		
		if (empty($result) || empty($result[$model])) {
			return false;
		}
		$user = $result[$model];
		unset($result[$model]);
		return array_merge($user, $result);
	}

	/**
	 * Create an encrypted Rijndael password.
	 *
	 * NOTE: for security purposes the plain-text password isn't actually encrypted, so IF
	 * the cyphertext would ever be broken, the password would still be 'safe'.
	 *
	 * @param type $username The username used for 'signing' the password.
	 * @param type $password The password that needs to be encrypted.
	 * @return array(pass=>'', iv=>'');
	 * @throws Exception When no suitable encryption libraries are found.
	 */
	public static function createEncryptedPassword($username, $password) {
		self::_getCakeSalt();
		
		if (extension_loaded("mcrypt")) {
			$iv = self::_generateIV();
			$key = self::createKey($username . $password . self::$SALT);
			$pass = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $username.self::$SALT, MCRYPT_MODE_CBC, $iv);
		} elseif (extension_loaded('openssl') && function_exists('openssl_encrypt')) {
			$pass = openssl_encrypt($password, 'AES-256-CBC', self::createKey($username . $password . self::$SALT), true);
			$iv = NULL;
		} else {
			throw new Exception("No suitable cryptography library found, You need to install Mcrypt or OpenSSL");
		}
		return base64_encode($pass).".". base64_encode($iv);
//		return array("pass" => base64_encode($pass), "iv" => base64_encode($iv));
	}

	/**
	 * Decrypt and verify the password.
	 *
	 * @param string $username Username used to 'sign' the password.
	 * @param string $password Plain-text version of the password that needs to be verified.
	 * @param string $iv base64 encoded version of the IV
	 * @param string $data base64 encoded version of the encrypted password.
	 * @return boolean TRUE when valid, FALSE when invalid
	 * @throws Exception When no suitable encryption libraries are found.
	 */
	protected function _decryptPWString($username, $password, $data) {
		$ex = explode(".", $data, 2);
		if($ex){
			$data = $ex[0];
			$iv = $ex[1];
		}

		if (extension_loaded('mcrypt')) {
			$dstring = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, self::createKey($username . $password . self::$SALT), base64_decode($data), MCRYPT_MODE_CBC, base64_decode($iv));
			var_dump($dstring);
		} elseif (extension_loaded('openssl') && function_exists('openssl_decrypt')) {
			$dstring = openssl_decrypt($data, 'AES-256-CBC', self::createKey($username . $password . self::$SALT));
		} else {
			throw new Exception("No suitable cryptography library found, You need to install Mcrypt or OpenSSL");
		}
		return trim($dstring) == $username.self::$SALT ? true : false;
	}

	/**
	 * Generate an IV for encryption
	 * @return string IV
	 */
	protected static function _generateIV(){
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC);
		return mcrypt_create_iv($iv_size, MCRYPT_RAND);
	}
	/**
	 * fill the static SALT variable with the SALT from the CakePHP core config.
	 *
	 * This function needs to be called by all static methods relying on the SALT variable being set,
	 * as the constructor for the class will not be called for static methods.
	 */
	protected static function _getCakeSalt(){
		self::$SALT = Configure::read('Security.salt');
	}

	/**
	 * Create a key for encryption
	 * @param type $string
	 * @return type
	 * @todo Use better keygenerator mhash, hash, etc.
	 */
	protected static function createKey($string){
		return md5($string);
	}
}

?>