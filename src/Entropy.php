<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.1.1
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker;

/**
 * Class Entropy
 *
 * @package NorseBlue\Sikker\Passwords
 * @since 0.2
 */
class Entropy
{
    /**
     * Calculates the character repeatability factor for the given token.
     * Important: The repeatability factor is depends on the length of the token.
     *
     * @param string $token The token to calculate the factor.
     * @return float Returns the calculated repeatability factor.
     * @since 0.2
     */
    public static function calculateRepeatFactor(string $token) : float
    {
        $tokenChars = str_split($token);
        $tokenLen = count($tokenChars);
        $chars = [];
        foreach ($tokenChars as $char) {
            $char = strval($char);
            if (key_exists($char, $chars)) {
                $chars[$char]++;
            } else {
                $chars[$char] = 1;
            }
        }

        $repeats = array_sum($chars) - count($chars);
        $factor = $repeats / $tokenLen;
        return $factor;
    }
}