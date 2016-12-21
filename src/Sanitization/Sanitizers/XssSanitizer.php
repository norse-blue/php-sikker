<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3.8
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Sanitization\Sanitizers;

/**
 * Class XssSanitizer
 *
 * @package NorseBlue\Sikker\Sanitization\Sanitizers
 * @since 0.4
 */
class XssSanitizer extends SanitizerBase
{
    /**
     * @var array Holds the supported XssSanitizer types for scrubbing.
     */
    const SUPPORTED_TYPES = ['string'];

    /**
     * Scrubs the string to prevent XSS attacks.
     *
     * @param string $data The data to be scrubbed.
     * @param array $options Additional options that may be needed.
     * @return string Returns the scrubbed data.
     */
    public function scrubString(string $data, array $options = []) : string
    {
        // TODO: clean the given string to prevent XSS attacks
        return '';
    }
}