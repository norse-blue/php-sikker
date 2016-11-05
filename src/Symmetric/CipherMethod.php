<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3.5
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
 * @see https://www.openssl.org/docs/manmaster/apps/enc.html#SUPPORTED_CIPHERS OpenSSL supported ciphers reference.
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
     * @var string Cipher method BLOWFISH
     */
    const BLOWFISH = 'BF';

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
     * @var string  Cipher method Triple DES with 2 keys
     */
    const DES3_2K = 'DES-EDE';

    /**
     * @var string  Cipher method Triple DES with 3 keys
     */
    const DES3_3K = 'DES-EDE3';

    /**
     * @var string  Cipher method  DESX
     */
    const DESX = 'DESX';

    /**
     * @var string  Cipher method IDEA
     */
    const IDEA = 'IDEA';

    /**
     * @var string  Cipher method RC2 (128 bits)
     */
    const RC2 = 'RC2';

    /**
     * @var string  Cipher method RC2 (64 bits)
     */
    const RC2_64 = 'RC2-64';

    /**
     * @var string  Cipher method RC2 (40 bits)
     */
    const RC2_40 = 'RC2-40';

    /**
     * @var string  Cipher method RC4 (128 bits)
     */
    const RC4 = 'RC4';

    /**
     * @var string  Cipher method RC4 (64 bits)
     */
    const RC4_64 = 'RC4-64';

    /**
     * @var string  Cipher method RC4 (40 bits)
     */
    const RC4_40 = 'RC4-40';

    /**
     * @var string Cipher method SEED
     */
    const SEED = 'SEED';

    /**
     * @var null|array List of the available methods or null if not initialized.
     */
    private static $availableMethods = null;

    /**
     * Trims the cipher mode from the given array of cipher methods.
     *
     * @param array $methods The cipher methods to trim mode from.
     * @return array Returns an array of cipher methods with trimmed mode.
     * @since 0.3.5
     */
    protected static function trimCipherMode(array $methods)
    {
        $regexMethods = '';
        foreach (CipherMode::NAMES as $mode => $modeName) {
            if ($mode != CipherMode::UNKNOWN) {
                $regexMethods .= sprintf('|%s', $modeName);
            }
        }

        $regex = sprintf('/^(.*)(-(?:%s))$/', trim(strtoupper($regexMethods), '|'));
        $ciphers = preg_replace($regex, '$1', $methods);
        return $ciphers ?? [];
    }

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
            $methods = array_unique(array_map('strtoupper', openssl_get_cipher_methods(true)));
            self::$availableMethods = array_unique(self::trimCipherMode($methods));
        }

        return self::$availableMethods;
    }
}