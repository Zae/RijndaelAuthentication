<?php
$config = array(
	'Encryption' => array(
		'extension' => 'mcrypt',
		'ciphername' => MCRYPT_RIJNDAEL_256,
		'ciphermode' => MCRYPT_MODE_CBC,
		'iv_source' => MCRYPT_RAND
	)
);
?>