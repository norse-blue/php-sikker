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
     * Gets the count of unique characters in a string.
     *
     * @param string $str The string to get the chars count from.
     * @return array Returns an array with the unique chars as the key and the count as the value.
     * @since 0.2
     */
    public static function charsCount(string $str)
    {
        if ($str == '') {
            return [];
        }

        $arrChars = preg_split('//u', $str, -1, PREG_SPLIT_NO_EMPTY);
        return array_count_values($arrChars);
    }

    /**
     * Calculates the character repeatability factor for a string.
     * Important: The repeatability factor depends on the length of the string.
     *
     * @param string $str The string to calculate the factor.
     * @return float Returns the calculated repeatability factor.
     * @since 0.2
     */
    public static function repeatFactor(string $str) : float
    {
        $strLen = (function_exists('mb_strlen')) ? mb_strlen($str) : strlen($str);
        $arrCharsCount = self::charsCount($str);
        $uniqueChars = count($arrCharsCount);
        if ($uniqueChars == $strLen) {
            return 0;
        } elseif ($uniqueChars == 1) {
            return 1;
        }

        $repeats = 0;
        foreach ($arrCharsCount as $char => $value) {
            if ($value > 1) {
                $repeats += $value;
            }
        }

        $factor = $repeats / $strLen;
        return $factor;
    }
}