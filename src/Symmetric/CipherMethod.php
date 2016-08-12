<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Symmetric;

use NorseBlue\Sikker\OpenSSL\OpenSSL;

/**
 * Class CipherMethod
 *
 * @package NorseBlue\Sikker\Symmetric
 * @see http://php.net/manual/en/function.openssl-get-cipher-methods.php openssl_get_cipher_methods function reference.
 * @since 0.3
 */
abstract class CipherMethod
{
    /**
     * @var string Cipher method AES 128bit
     */
    const AES128 = 'AES128';

    /**
     * @var string Cipher method AES 192bit
     */
    const AES192 = 'AES192';

    /**
     * @var string Cipher method AES 256bit
     */
    const AES256 = 'AES256';

    /**
     * @var string Cipher method BF
     */
    const BF = 'BF';

    /**
     * @var string Cipher method CAMELLIA 128bit
     */
    const CAMELLIA128 = 'CAMELLIA128';

    /**
     * @var string Cipher method CAMELLIA 192bit
     */
    const CAMELLIA192 = 'CAMELLIA192';

    /**
     * @var string Cipher method CAMELLIA 256bit
     */
    const CAMELLIA256 = 'CAMELLIA256';

    /**
     * @var string  Cipher method CAST
     */
    const CAST = 'CAST';

    /**
     * @var string  Cipher method CAST
     */
    const DES = 'DES';

    /**
     * @var string  Cipher method Triple DES
     */
    const DES3 = 'DES3';

    /**
     * @var string  Cipher method  DESX
     */
    const DESX = 'DESX';

    /**
     * @var string  Cipher method IDEA
     */
    const IDEA = 'IDEA';

    /**
     * @var string  Cipher method RC2
     */
    const RC2 = 'RC2';

    /**
     * @var string  Cipher method RC4
     */
    const RC4 = 'RC4';

    /**
     * @var string Cipher method SEED
     */
    const SEED = 'SEED';

    /**
     * @var string Cipher mode EBC
     */
    const MODE_EBC = 'EBC';

    /**
     * @var string Cipher mode EBC
     */
    const MODE_CBC = 'CBC';

    /**
     * @var null|array List of the available methods or null if not initialized.
     */
    private static $availableMethods = null;

    /**
     * Verifies if the given method is available.
     *
     * @param string $method The method to check for.
     * @return bool Returns true if the method is available, false otherwise.
     * @since 0.1
     */
    public static function isAvailable(string $method) : bool
    {
        OpenSSL::isAvailable(true);
        return (in_array($method, self::allAvailable()));
    }

    /**
     * Gets all the supported cipher methods.
     *
     * @return array Returns a numerically indexed array containing the list of supported cipher methods.
     * @since 0.1
     */
    public static function allAvailable() : array
    {
        OpenSSL::isAvailable(true);
        if (self::$availableMethods === null) {
            $ciphers = array_diff(openssl_get_cipher_methods(true), openssl_get_cipher_methods()) + ['RC4'];
            $ciphers = array_unique(array_map('strtoupper', $ciphers));
            self::$availableMethods = [];
            foreach ($ciphers as $cipher) {
                if (preg_match('/^(\w+)$/', $cipher)) {
                    self::$availableMethods[] = $cipher;
                }
            }
        }

        return self::$availableMethods;
    }
}