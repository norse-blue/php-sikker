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
     * Splits the given string into an array of chars.
     *
     * @param string $str The string to split.
     * @return array Returns an array of chars contained in the string in the original order.
     * @since 0.2
     */
    public static function splitChars(string $str) : array
    {
        if ($str == '') {
            return [];
        }

        return preg_split('//u', $str, -1, PREG_SPLIT_NO_EMPTY);
    }

    /**
     * Gets the count of unique characters in a string.
     *
     * @param string $str The string to get the chars count from.
     * @return array Returns an array with the unique chars as the key and the count as the value.
     * @since 0.2
     */
    public static function charCounts(string $str) : array
    {
        return array_count_values(self::splitChars($str));
    }

    /**
     * Calculates the distance of separation between repeated chars in the string.
     *
     * @param string $str The string to calculate the separation distances from.
     * @param bool $includeAllChars Whether to include non-repeated chars also.
     * @return array Returns the distances between repeated characters in the string for each repeated char.
     * @since 0.2
     */
    public static function charDistances(string $str, bool $includeAllChars = false) : array
    {
        if ($str == '') {
            return [];
        }

        $funcStrPos = function (string $haystack, string $needle, int $offset = 0) {
            return ((function_exists('mb_strpos')) ? mb_strpos($haystack, $needle, $offset) : strpos($haystack, $needle,
                $offset));
        };

        $sepDegrees = [];
        $charsCount = self::charCounts($str);
        foreach ($charsCount as $char => $charTimes) {
            if (!$includeAllChars && $charTimes < 2) {
                continue;
            }

            $sepDegrees[$char] = [];
            $currChar = $funcStrPos($str, $char);
            $nextChar = 0;
            while ($nextChar > -1) {
                $nextChar = $funcStrPos($str, $char, $currChar + 1);
                if ($nextChar > 0) {
                    $sepDegrees[$char][] = $nextChar - $currChar;
                    $currChar = $nextChar;
                }
            }
        }

        return $sepDegrees;
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
        $arrCharsCount = self::charCounts($str);
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