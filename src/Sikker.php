<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.2
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker;

/**
 * Class Sikker
 *
 * @package NorseBlue\Sikker
 * @since 0.1
 */
abstract class Sikker
{
    /**
     * @var string Sikker packge version.
     */
    const VERSION = '0.1.1';

    /**
     * @var bool|null Whether OpenSSL module is available.
     */
    protected static $openSSLAvailable = null;

    /**
     * Verifies if the OpenSSL extension is loaded.
     *
     * @return bool Whether the OpenSSL extension is loaded or not.
     * @since 0.1
     * @codeCoverageIgnore Ignore as it is platform dependent.
     */
    public static function isOpenSSLAvailable() : bool
    {
        if (self::$openSSLAvailable == null) {
            extension_loaded('openssl');
        }

        return self::$openSSLAvailable;
    }

    /**
     * Get string length. Uses multi-byte function if exists.
     *
     * @param string $str The string being measured for length.
     * @return int The length of the string on success, and 0 if the string is empty.
     */
    public static function strlen(string $str) : int
    {
        return (function_exists('mb_strlen')) ? mb_strlen($str) : strlen($str);
    }

    /**
     * Find the position of the first occurrence of a substring in a string. Uses multi-byte function if exists.
     *
     * @param string $haystack The string to search in.
     * @param mixed $needle If needle is not a string, it is converted to an integer and applied as the ordinal value of a character.
     * @param int $offset If specified, search will start this number of characters counted from the beginning of the string. Unlike strrpos() and strripos(), the offset cannot be negative.
     * @return mixed Returns the position of where the needle exists relative to the beginning of the haystack string (independent of offset). Also note that string positions start at 0, and not 1. Returns false if the needle was not found.
     */
    public static function strpos(string $haystack, $needle, int $offset = 0)
    {
        return (function_exists('mb_strpos'))
            ? mb_strpos($haystack, $needle, $offset)
            : strpos($haystack, $needle, $offset);
    }
}