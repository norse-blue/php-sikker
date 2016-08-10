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

namespace NorseBlue\Sikker\Entropy;

use NorseBlue\Sikker\Entropy\Adapters\EntropyAdapter;
use NorseBlue\Sikker\Entropy\Adapters\EntropyAdapterSimple;
use NorseBlue\Sikker\Sikker;

/**
 * Class Entropy
 *
 * @package NorseBlue\Sikker\Entropy
 * @since 0.2
 */
class Entropy
{
    /**
     * @var string Character class digits.
     */
    const CHAR_CLASS_DIGITS = '0123456789';

    /**
     * @var string Character class upper case ascii letters.
     */
    const CHAR_CLASS_UPPERCASE_ASCII = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /**
     * @var string Character class lower case ascii letters.
     */
    const CHAR_CLASS_LOWERCASE_ASCII = 'abcdefghijklmnopqrstuvwxyz';

    /**
     * @var string Character class ascii symbols.
     */
    const CHAR_CLASS_SYMBOLS_ASCII = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';

    /**
     * @var EntropyAdapter The entropy adapter to use for estimation.
     */
    protected $adapter;

    /**
     * Entropy constructor.
     *
     * @param EntropyAdapter|null $adapter The entropy adapter to use for estimation.
     * @since 0.2
     */
    public function __construct(EntropyAdapter $adapter = null)
    {
        $this->setAdapter($adapter);
    }

    /**
     * Measures the given char distances in string.
     *
     * @param string $str The string to measure the char distances of.
     * @param string $char The char to measure the distances from.
     * @return array Returns an array of char distances.
     * @since 0.2
     */
    protected static function measureCharDistances(string $str, string $char) : array
    {
        $charDistances = [];
        $currChar = Sikker::strpos($str, $char);
        do {
            $nextChar = Sikker::strpos($str, $char, $currChar + 1);
            if ($nextChar > $currChar) {
                $charDistances[] = $nextChar - $currChar;
                $currChar = $nextChar;
            }
        } while ($nextChar !== false);

        return $charDistances;
    }

    /**
     * Aggregates the count value of every char, filtering the ones that are not repeated.
     *
     * @param array $charsCounts The char count array.
     * @return int Returns the aggregate number of repeated chars.
     * @since 0.2
     */
    protected static function countCharRepeats(array $charsCounts) : int
    {
        $repeats = 0;
        foreach ($charsCounts as $char => $value) {
            if ($value > 1) {
                $repeats += (int) $value;
            }
        }

        return $repeats;
    }

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
    public static function charsCounts(string $str) : array
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
    public static function charsDistances(string $str, bool $includeAllChars = false) : array
    {
        $sepDegrees = [];
        $charsCount = self::charsCounts($str);
        foreach ($charsCount as $char => $charTimes) {
            if ($includeAllChars || $charTimes > 1) {
                $sepDegrees[$char] = self::measureCharDistances($str, $char);
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
        $strLen = Sikker::strlen($str);
        $arrCharsCount = self::charsCounts($str);
        $uniqueChars = count($arrCharsCount);
        if ($uniqueChars == 1) {
            return 1;
        } elseif ($uniqueChars == $strLen) {
            return 0;
        }

        $factor = self::countCharRepeats($arrCharsCount) / $strLen;
        return $factor;
    }

    /**
     * Gets the spatial dimension of the given string.
     *
     * @param string $str The string toi get the spatial dimension of.
     * @return int Returns the spatial dimension.
     * @since 0.2
     */
    public static function spatialDimension(string $str) : int
    {
        $spatial = 0;
        $charClasses = [
            Entropy::CHAR_CLASS_DIGITS,
            Entropy::CHAR_CLASS_LOWERCASE_ASCII,
            Entropy::CHAR_CLASS_UPPERCASE_ASCII,
            Entropy::CHAR_CLASS_SYMBOLS_ASCII
        ];

        foreach ($charClasses as $charClass) {
            if (preg_match('/['.preg_quote($charClass, '/').']/', $str) === 1) {
                $spatial += Sikker::strlen($charClass);
            }
        }

        return $spatial;
    }

    /**
     * Gets the EntropyAdapter.
     *
     * @return EntropyAdapter The loaded EntropyAdapter.
     * @since 0.2
     */
    public function getAdapter() : EntropyAdapter
    {
        return $this->adapter;
    }

    /**
     * Sets the EntropyAdapter.
     *
     * @param EntropyAdapter|null $adapter The new EntropyAdapter
     * @return Entropy Return this instance for fluent interface.
     * @since 0.2
     */
    public function setAdapter(EntropyAdapter $adapter = null) : Entropy
    {
        $this->adapter = $adapter ?? new EntropyAdapterSimple();
        return $this;
    }

    /**
     * Estimates the entropy of the given string using the loaded EntropyAdapter.
     *
     * @param string $str The string to calculate the entropy of.
     * @return float Returns the estimated entropy.
     * @since 0.2
     */
    public function estimate(string $str) : float
    {
        return $this->adapter->estimateEntropy($str);
    }
}