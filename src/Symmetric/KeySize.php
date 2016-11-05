<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3.6
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Symmetric;

/**
 * Class KeySize
 *
 * @package NorseBlue\Sikker\Symmetric
 * @see http://php.net/manual/en/function.openssl-get-cipher-methods.php openssl_get_cipher_methods function reference.
 * @see https://www.openssl.org/docs/manmaster/apps/enc.html#SUPPORTED_CIPHERS OpenSSL supported ciphers reference.
 * @since 0.3.5
 */
abstract class KeySize
{
    /**
     * @var int Unknown key size.
     */
    const UNKNOWN = -1;

    /**
     * @var int 40 bit key size.
     */
    const _40 = 40;

    /**
     * @var int 64 bit key size.
     */
    const _64 = 64;

    /**
     * @var int 128 bit key size.
     */
    const _128 = 128;

    /**
     * @var int 192 bit key size.
     */
    const _192 = 192;

    /**
     * @var int 256 bit key size.
     */
    const _256 = 256;

    /**
     * @var array Holds the key sizes names.
     */
    const NAMES = [
        self::UNKNOWN => 'unknown',
        self::_40 => '40 bit',
        self::_64 => '64 bit',
        self::_128 => '128 bit',
        self::_192 => '192 bit',
        self::_256 => '256 bit',
    ];

    /**
     * Gets the key size as a string.
     *
     * @param int $value The key size value.
     * @return string Returns the key size as string.
     * @since 0.3.5
     */
    public static function asString(int $value) : string
    {
        if (array_key_exists($value, self::NAMES)) {
            return self::NAMES[$value];
        }
        return self::NAMES[self::UNKNOWN];
    }

    /**
     * Gets the key size as value.
     *
     * @param string $str The key size string.
     * @return int Returns the key size as value.
     * @since 0.3.5
     */
    public static function asValue(string $str) : int
    {
        $items = array_flip(self::NAMES);
        if (array_key_exists($str, $items)) {
            return $items[$str];
        }
        $value = is_numeric($str) ? intval($str) : self::UNKNOWN;
        if (in_array($value, self::NAMES)) {
            return $value;
        }
        return self::UNKNOWN;
    }
}