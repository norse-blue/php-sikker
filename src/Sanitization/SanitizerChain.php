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

namespace NorseBlue\Sikker\Sanitization;

use Exception;
use InvalidArgumentException;
use RuntimeException;

/**
 * Class SanitizerChain
 *
 * @package NorseBlue\Sikker\Sanitization
 * @since 0.4
 */
class SanitizerChain
{
    /**
     * @var array Holds the sanitizers in the chain.
     */
    protected $sanitizers;

    /**
     * SanitizerChain constructor.
     *
     * @param array $sanitizers The array of sanitizers to use for the chain.
     * @since 0.4
     */
    public function __construct(array $sanitizers = [])
    {
        $this->setSanitizers($sanitizers);
    }

    /**
     * Gets the sanitizers.
     *
     * @return array Returns the array of sanitizers.
     */
    public function getSanitizers() : array
    {
        return $this->sanitizers;
    }

    /**
     * Sets the sanitizers array.
     *
     * @param array $sanitizers The array of sanitizers.
     * @return SanitizerChain Returns this instance for fluent interface.
     * @throws InvalidArgumentException when a sanitizer is not of type Sanitizer.
     */
    public function setSanitizers(array $sanitizers) : SanitizerChain
    {
        $sanitizersCount = count($sanitizers);
        for ($i = 0; $i < $sanitizersCount; $i++) {
            if (!($sanitizers[$i] instanceof Sanitizer)) {
                throw new InvalidArgumentException(sprintf('Expected an item of type %s at index %d but type %s found.',
                    Sanitizer::class, $i, gettype($sanitizers[$i])));
            }
        }
        $this->sanitizers = $sanitizers;
        return $this;
    }

    /**
     * Runs the sanitizer chain on the given data.
     *
     * @param mixed $data The given data to scrub.
     * @return mixed Returns the scrubbed data.
     */
    public function sweep($data)
    {
        $cleanData = $data;
        $sanitizersCount = count($this->sanitizers);
        for ($i = 0; $i < $sanitizersCount; $i++) {
            try {
                $cleanData = $this->sanitizers[$i]->scrub($cleanData);
            } catch (Exception $e) {
                throw new RuntimeException(sprintf('Sanitizer of type %s at index %d caused an error while scrubbing the data.',
                    gettype($this->sanitizers[$i]), $i), 0, $e);
            }
        }

        return $cleanData;
    }
}