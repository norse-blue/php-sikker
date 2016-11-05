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

namespace NorseBlue\Sikker\Sanitization;

use RuntimeException;

/**
 * Interface Sanitizer
 *
 * @package NorseBlue\Sikker\Sanitization
 * @since 0.4
 */
interface Sanitizer
{
    /**
     * Determines if the sanitizer supports scrub operation on given type.
     *
     * @param string $type The type to check for scrub support.
     * @return bool Returns true if the sanitizer supports scrub operation on given type, false otherwise.
     */
    public function isTypeSupported(string $type) : bool;

    /**
     * Determines the type of data and uses the specific scrub function to clean data.
     *
     * @param mixed $data The data to be scrubbed.
     * @return mixed Returns the scrubbed data.
     * @throws RuntimeException when no scrub function can be executed.
     */
    public function scrub($data);

    /**
     * Scrubs an array data.
     *
     * @param array $data The data to be scrubbed.
     * @return array Returns the scrubbed data.
     * @throws RuntimeException when the sanitizer does not support this specific scrub operation.
     */
    public function scrubArray(array $data) : array;

    /**
     * Scrubs a boolean data.
     *
     * @param bool $data The data to be scrubbed.
     * @return bool Returns the scrubbed data.
     * @throws RuntimeException when the sanitizer does not support this specific scrub operation.
     */
    public function scrubBool(bool $data) : bool;

    /**
     * Scrubs a float (double) data.
     *
     * @param float $data The data to be scrubbed.
     * @return float Returns the scrubbed data.
     * @throws RuntimeException when the sanitizer does not support this specific scrub operation.
     */
    public function scrubFloat(float $data) : float;

    /**
     * Scrubs an integer data.
     *
     * @param int $data The data to be scrubbed.
     * @return int Returns the scrubbed data.
     * @throws RuntimeException when the sanitizer does not support this specific scrub operation.
     */
    public function scrubInt(int $data) : int;

    /**
     * Scrubs an object data.
     *
     * @param object $data The data to be scrubbed.
     * @return object Returns the scrubbed data.
     * @throws RuntimeException when the sanitizer does not support this specific scrub operation.
     */
    public function scrubObject(object $data) : object;

    /**
     * Scrubs a string data.
     *
     * @param string $data The data to be scrubbed.
     * @return string Returns the scrubbed data.
     * @throws RuntimeException when the sanitizer does not support this specific scrub operation.
     */
    public function scrubString(string $data) : string;
}