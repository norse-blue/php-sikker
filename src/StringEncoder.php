<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3.7
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker;

use InvalidArgumentException;

/**
 * Class Hex
 *
 * @package NorseBlue\Sikker
 * @since 0.3.5
 */
abstract class StringEncoder
{
    /**
     * Converts the given raw string to it's hex form.
     *
     * @param string $raw The raw string to convert.
     * @return string Returns the converted hex string.
     * @since 0.3.5
     */
    public static function rawToHex(string $raw) : string
    {
        return bin2hex($raw);
    }

    /**
     * Converts the given hex string to it's raw form.
     *
     * @param string $hex The hex string to convert.
     * @return string Returns the converted raw string.
     * @since 0.3.5
     */
    public static function hexToRaw(string $hex) : string
    {
        return hex2bin($hex);
    }

    /**
     * Converts the given raw string to it's base64 form.
     *
     * @param string $raw The raw string to convert.
     * @return string Returns the converted base64 string.
     * @since 0.3.5
     */
    public static function rawToBase64(string $raw) : string
    {
        return base64_encode($raw);
    }

    /**
     * Converts the given base64 string to it's raw form.
     *
     * @param string $base64 The base64 string to convert.
     * @return string Returns the converted raw string.
     * @throws InvalidArgumentException when the given string is not a correctly encoded base64 string.
     * @since 0.3.5
     */
    public static function base64ToRaw(string $base64) : string
    {
        if (($raw = base64_decode($base64, true)) === false) {
            throw new InvalidArgumentException('The given string is not a correctly encoded base64 string.');
        }

        return $raw;
    }
}