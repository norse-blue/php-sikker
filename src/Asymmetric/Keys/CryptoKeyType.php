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

namespace NorseBlue\Sikker\Asymmetric\Keys;

/**
 * Class CryptoKeyType
 *
 * @package NorseBlue\Sikker\Asymmetric\Keys
 * @see http://php.net/manual/en/function.openssl-pkey-get-details.php openssl_pkey_get_details function reference.
 * @since 0.3
 */
abstract class CryptoKeyType
{
    /**
     * @var int Unknown KeyType
     */
    const UNKNOWN = -1;

    /**
     * @var int KeyType RSA (matches constant OPENSSL_KEYTYPE_RSA)
     */
    const RSA = 0;

    /**
     * @var int KeyType DSA (matches constant OPENSSL_KEYTYPE_DSA)
     */
    const DSA = 1;

    /**
     * @var int KeyType DH (matches constant OPENSSL_KEYTYPE_DH)
     */
    const DH = 2;

    /**
     * @var int KeyType EC (matches constant OPENSSL_KEYTYPE_EC)
     */
    const EC = 3;

    /**
     * @var array Holds the key types names.
     */
    const NAMES = [
        self::UNKNOWN => 'unknown',
        self::RSA => 'rsa',
        self::DSA => 'dsa',
        self::DH => 'dh',
        self::EC => 'ec'
    ];

    /**
     * Gets the key type as a string.
     *
     * @param int $value The type to get as string.
     * @return string Returns the key type as a string.
     * @since 0.3
     */
    public static function toName(int $value) : string
    {
        if (array_key_exists($value, self::NAMES)) {
            return self::NAMES[$value];
        }
        return self::NAMES[self::UNKNOWN];
    }

    /**
     * Gets the key type as an integer from the name.
     *
     * @param string $name The name of the key type.
     * @return int Returns the integer value of the key type.
     * @since 0.3
     */
    public static function fromName(string $name) : int
    {
        $items = array_flip(self::NAMES);
        if (array_key_exists($name, $items)) {
            return $items[$name];
        }
        return self::UNKNOWN;
    }
}