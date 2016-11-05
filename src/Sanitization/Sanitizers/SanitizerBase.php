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

namespace NorseBlue\Sikker\Sanitization\Sanitizers;

use InvalidArgumentException;
use NorseBlue\Sikker\Sanitization\Sanitizer;
use RuntimeException;

/**
 * Class SanitizerBase
 *
 * @package NorseBlue\Sikker\Sanitization\Sanitizers
 * @since 0.4
 */
abstract class SanitizerBase implements Sanitizer
{
    /**
     * @var array Holds the supported types for scrubbing (bool, int, float, string, array or object).
     */
    const SUPPORTED_TYPES = [];

    /**
     * Determines if the sanitizer supports scrub operation on given type.
     *
     * @param string $type The type to check for scrub support.
     * @return bool Returns true if the sanitizer supports scrub operation on given type, false otherwise.
     */
    public function isTypeSupported(string $type) : bool
    {
        return in_array($type, self::SUPPORTED_TYPES);
    }

    /**
     * Determines the type of data and uses the specific scrub function to clean data.
     *
     * @param mixed $data The data to be scrubbed.
     * @return mixed Returns the scrubbed data.
     * @throws InvalidArgumentException when the given data type is not supported by the sanitizer.
     */
    public function scrub($data)
    {
        if ($data === null || is_resource($data)) {
            return $data;
        }

        $type = gettype($data);
        if (!$this->isTypeSupported($type)) {
            throw new InvalidArgumentException('The given data type is not supported by the sanitizer.');
        }

        return $this->executeTypedScrub($type, $data);
    }

    /**
     * Executes the typed scrub with the given data.
     *
     * @param string $type The type of the data.
     * @param mixed $data The data to scrub.
     * @return mixed Returns the scrubbed data.
     * @throws RuntimeException when no scrub function can be executed.
     */
    protected function executeTypedScrub(string $type, $data)
    {
        $typedScrub = 'scrub'.($type == 'double') ? 'Float' : ucfirst($type);
        if (is_callable([$this, $typedScrub])) {
            return $this->{$typedScrub}($data);
        }

        throw new RuntimeException(sprintf('No %s typed scrub function cannot be executed.', $type));
    }

    /**
     * Scrubs an array data.
     *
     * @param array $data The data to be scrubbed.
     * @return array Returns the scrubbed data.
     * @throws RuntimeException when the sanitizer does not support this specific scrub operation.
     */
    public function scrubArray(array $data) : array
    {
        throw new RuntimeException(sprintf('This sanitizer does not support the %s operation.'), __FUNCTION__);
    }

    /**
     * Scrubs a boolean data.
     *
     * @param bool $data The data to be scrubbed.
     * @return bool Returns the scrubbed data.
     * @throws RuntimeException when the sanitizer does not support this specific scrub operation.
     */
    public function scrubBool(bool $data) : bool
    {
        throw new RuntimeException(sprintf('This sanitizer does not support the %s operation.'), __FUNCTION__);
    }

    /**
     * Scrubs a float (double) data.
     *
     * @param float $data The data to be scrubbed.
     * @return float Returns the scrubbed data.
     * @throws RuntimeException when the sanitizer does not support this specific scrub operation.
     */
    public function scrubFloat(float $data) : float
    {
        throw new RuntimeException(sprintf('This sanitizer does not support the %s operation.'), __FUNCTION__);
    }

    /**
     * Scrubs an integer data.
     *
     * @param int $data The data to be scrubbed.
     * @return int Returns the scrubbed data.
     * @throws RuntimeException when the sanitizer does not support this specific scrub operation.
     */
    public function scrubInt(int $data) : int
    {
        throw new RuntimeException(sprintf('This sanitizer does not support the %s operation.'), __FUNCTION__);
    }

    /**
     * Scrubs an object data.
     *
     * @param object $data The data to be scrubbed.
     * @return object Returns the scrubbed data.
     * @throws RuntimeException when the sanitizer does not support this specific scrub operation.
     */
    public function scrubObject(object $data) : object
    {
        throw new RuntimeException(sprintf('This sanitizer does not support the %s operation.'), __FUNCTION__);
    }

    /**
     * Scrubs a string data.
     *
     * @param string $data The data to be scrubbed.
     * @return string Returns the scrubbed data.
     * @throws RuntimeException when the sanitizer does not support this specific scrub operation.
     */
    public function scrubString(string $data) : string
    {
        throw new RuntimeException(sprintf('This sanitizer does not support the %s operation.'), __FUNCTION__);
    }
}