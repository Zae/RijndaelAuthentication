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

App::uses('ModelBehavior', 'Model');
App::uses('RijndaelAuthenticate', 'RijndaelAuthentication.Controller/Component/Auth');
class RijndaelAuthenticateBehavior extends ModelBehavior {
   /**
	 * Create an encrypted password based on the username and plain-text password of a user.
	 *
	 * @param string $username
	 * @param string $password
	 * @return array(pass=>'', iv=>'')
	 * @uses RijndaelAuthenticate::createEncryptedPassword
	 */
	public function createEncryptedPassword($model, $user, $pass) {
		return RijndaelAuthenticate::createEncryptedPassword($user, $pass);
	}
}
?>