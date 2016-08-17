<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3.5
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Entropy\Adapters;

use NorseBlue\Sikker\Entropy\Entropy;
use NorseBlue\Sikker\Sikker;

/**
 * Class EntropyAdapterSimple
 *
 * @package NorseBlue\Sikker\Entropy\Adapters
 * @see https://pthree.org/2011/03/07/strong-passwords-need-entropy/ Strong Passwords NEED Entropy by Aaron Toponce
 * @since 0.2
 */
class EntropyAdapterSimple implements EntropyAdapter
{
    /**
     * Estimates the entropy of the given string.
     * Uses a simple entropy approach. H = L * log_2(N) | L = length, N = possible symbols.
     *
     * @see https://pthree.org/2011/03/07/strong-passwords-need-entropy/ Strong Passwords NEED Entropy by Aaron Toponce
     * @param string $str The string to estimate the entropy of.
     * @return int Returns the estimated entropy in number of bits.
     * @since 0.2
     */
    public function estimateEntropy(string $str) : int
    {
        $spatial = Entropy::spatialDimension($str);
        return (int) floor(Sikker::strlen($str) * log($spatial, 2));
    }
}