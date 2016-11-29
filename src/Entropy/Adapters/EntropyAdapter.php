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

namespace NorseBlue\Sikker\Entropy\Adapters;

/**
 * Interface EntropyAdapter
 *
 * @package NorseBlue\Sikker\Entropy\Adapters
 * @since 0.2
 */
interface EntropyAdapter
{
    /**
     * Estimates the entropy of the given string.
     *
     * @param string $str The string to estimate the entropy of.
     * @return int Returns the estimated entropy in number of bits.
     * @since 0.2
     */
    public function estimateEntropy(string $str) : int;
}