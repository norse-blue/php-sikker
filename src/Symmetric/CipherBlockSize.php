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

/**
 * Class CipherBlockSize
 *
 * @package NorseBlue\Sikker\Symmetric
 * @see http://php.net/manual/en/function.openssl-get-cipher-methods.php openssl_get_cipher_methods function reference.
 * @since 0.3.5
 */
abstract class CipherBlockSize
{
    /**
     * @var int Unknown block size.
     */
    const UNKNOWN = -1;

    /**
     * @var int 40 bit block size.
     */
    const _40 = 40;

    /**
     * @var int 64 bit block size.
     */
    const _64 = 64;

    /**
     * @var int 128 bit block size.
     */
    const _128 = 128;

    /**
     * @var int 192 bit block size.
     */
    const _192 = 192;

    /**
     * @var int 256 bit block size.
     */
    const _256 = 256;

    /**
     * @var array Holds the block size names.
     */
    const NAMES = [
        self::UNKNOWN => 'unknown',
        self::_40 => '40',
        self::_64 => '64',
        self::_128 => '128',
        self::_192 => '192',
        self::_256 => '256',
    ];

    /**
     * Gets the cipher mode as a string.
     *
     * @param int $value The cipher mode to get as string.
     * @return string Returns the cipher mode as a string.
     * @since 0.3.5
     */
    public static function toName(int $value) : string
    {
        if (array_key_exists($value, self::NAMES)) {
            return self::NAMES[$value];
        }
        return self::NAMES[self::UNKNOWN];
    }

    /**
     * Gets the cipher mode as an integer from the name.
     *
     * @param string $name The name of the cipher mode.
     * @return int Returns the integer value of the cipher mode.
     * @since 0.3.5
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