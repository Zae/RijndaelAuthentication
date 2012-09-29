<?php
/**
 * @copyright (c) 2012, Ezra Pool <ezra@tsdme.nl>
 * @license LGPL v3
 *
 * This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

App::uses('BaseAuthenticate', 'Controller/Component/Auth');
class RijndaelAuthenticate extends BaseAuthenticate {
	const version = '0.0.1';

	const EXT_MCRYPT = 'mcrypt';
	const EXT_OPENSSL = 'openssl';
	
	protected static $config;

	public function __construct(ComponentCollection $collection, $settings) {
		self::_getCakeConfig();
		
		parent::__construct($collection, $settings);
	}

	public function authenticate(CakeRequest $request, CakeResponse $response){
		try{
			$fields = $this->settings['fields'];
			list($plugin, $model) = pluginSplit($this->settings['userModel']);

			$user = $this->_findUser($request->data[$model][$fields['username']]);

			if($this->_decryptPWString($request->data[$model][$fields['username']], $request->data[$model][$fields['password']], $user[$fields['password']])){
				return $user;
			}
		} catch (Exception $e) {CakeLog::error($e);}

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
	 * the ciphertext would ever be broken, the password would still be 'safe'.
	 *
	 * @param type $username The username used for 'signing' the password.
	 * @param type $password The password that needs to be encrypted.
	 * @return array(pass=>'', iv=>'');
	 * @throws Exception When no suitable encryption libraries are found.
	 */
	public static function createEncryptedPassword($username, $password) {
		self::_getCakeConfig();
		
		if (self::$config['Encryption']['extension'] == self::EXT_MCRYPT && extension_loaded("mcrypt")) {
			$iv = self::_generateIV();
			$key = self::createKey($username . $password . self::$config['SALT']);
			$pass = mcrypt_encrypt(self::$config['Encryption']['ciphername'], $key, $username.self::$config['SALT'], self::$config['Encryption']['ciphermode'], $iv);
		} elseif (self::$config['Encryption']['extension'] == self::EXT_OPENSSL && extension_loaded('openssl') && function_exists('openssl_encrypt')) {
			$pass = openssl_encrypt($password, self::$config['Encryption']['ciphername'], self::createKey($username . $password . self::$config['SALT']), true);
			$iv = NULL;
		} else {
			throw new Exception("No suitable cryptography library found, You need to install Mcrypt or OpenSSL");
		}
		return base64_encode($pass).".". base64_encode($iv);
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

		if (self::$config['Encryption']['extension'] == self::EXT_MCRYPT && extension_loaded('mcrypt')) {
			$dstring = mcrypt_decrypt(self::$config['Encryption']['ciphername'], self::createKey($username . $password . self::$config['SALT']), base64_decode($data), self::$config['Encryption']['ciphermode'], base64_decode($iv));
		} elseif (self::$config['Encryption']['extension'] == self::EXT_OPENSSL && extension_loaded('openssl') && function_exists('openssl_decrypt')) {
			$dstring = openssl_decrypt($data, self::$config['Encryption']['ciphername'], self::createKey($username . $password . self::$config['SALT']));
		} else {
			throw new Exception("No suitable cryptography library found, You need to install Mcrypt or OpenSSL");
		}

		return trim($dstring) == $username.self::$config['SALT'] ? true : false;
	}

	/**
	 * Generate an IV for encryption
	 * @return string IV
	 */
	protected static function _generateIV(){
		$iv_size = mcrypt_get_iv_size(self::$config['Encryption']['ciphername'], self::$config['Encryption']['ciphermode']);
		return mcrypt_create_iv($iv_size, self::$config['Encryption']['iv_source']);
	}
	/**
	 * fill the static config variable with the config options from core config and encryption config from plugin.
	 *
	 * This function needs to be called by all static methods relying on the config variable being set
	 * as the constructor for the class will not be called for static methods.
	 */

	protected static function _getCakeConfig(){
		self::$config['SALT'] = Configure::read('Security.salt');

		Configure::load('RijndaelAuthentication.encryption');
		self::$config['Encryption'] = Configure::read('Encryption');
	}

	/**
	 * Create a key for encryption
	 * @param type $string
	 * @return type
	 * @todo Use better keygenerator mhash, hash, etc.
	 */
	protected static function createKey($string){
		self::_getCakeConfig();

		$hash = function_exists('hash');
		$hash_algos = $hash ? hash_algos() : array();

		$key = md5($string, TRUE);

		if (self::$config['Encryption']['extension'] == self::EXT_MCRYPT && extension_loaded('mcrypt')) {
			$key_size = mcrypt_get_key_size(self::$config['Encryption']['ciphername'], self::$config['Encryption']['ciphermode']);

			switch(true){
				case ($key_size >= 64 && $hash && in_array('sha512', $hash_algos)):
					$key = hash('sha512', $string, TRUE);
					break;
				case ($key_size >= 32 && $hash && in_array('sha256', $hash_algos)):
					$key = hash('sha256', $string, TRUE);
					break;
				case ($key_size >= 20):
					$key = sha1($string, TRUE);
					break;
				case ($key_size >= 16):
					$key = md5($string, TRUE);
					break;
			}
		} elseif (self::$config['Encryption']['extension'] == self::EXT_OPENSSL && extension_loaded('openssl') && function_exists('openssl_decrypt')) {
			switch(true){
				case ($hash && in_array('sha512', $hash_algos)):
					$key = hash('sha512', $string, TRUE);
					break;
				case ($hash && in_array('sha256', $hash_algos)):
					$key = hash('sha256', $string, TRUE);
					break;
				default:
					$key = sha1($string, TRUE);
					break;
			}
		}

		return $key;
	}
}

?>