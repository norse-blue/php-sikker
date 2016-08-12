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
 * Class CipherMode
 *
 * @package NorseBlue\Sikker\Symmetric
 * @see http://php.net/manual/en/function.openssl-get-cipher-methods.php openssl_get_cipher_methods function reference.
 * @since 0.3.5
 */
abstract class CipherMode
{
    /**
     * @var int Unknown mode.
     */
    const UNKNOWN = -1;

    /**
     * @var int The EBC mode.
     */
    const ECB = 0;

    /**
     * @var int The CBC mode.
     */
    const CBC = 1;

    /**
     * @var array Holds the modes names.
     */
    const NAMES = [
        self::UNKNOWN => 'unknown',
        self::ECB => 'ecb',
        self::CBC => 'cbc'
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