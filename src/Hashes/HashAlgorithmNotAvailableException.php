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

namespace NorseBlue\Sikker\Hashes;

use RuntimeException;
use Throwable;

/**
 * Class HashAlgorithmNotAvailableException
 *
 * @package NorseBlue\Sikker\Hashes
 * @see http://php.net/manual/en/class.runtimeexception.php The RuntimeException class
 * @since 0.1
 * @codeCoverageIgnore This class does not need to be covered by tests. It's just an extension to exceptions with an additional property and it's getter.
 */
class HashAlgorithmNotAvailableException extends RuntimeException
{
    /**
     * @var string The algorithm that was not found.
     */
    protected $algorithm;

    /**
     * HashAlgorithmNotAvailableException constructor.
     *
     * @param string $method The algorithm that was not found.
     * @param string $message The Exception message to throw. {@link http://php.net/manual/en/exception.construct.php Exception constructor}
     * @param int $code The Exception code. {@link http://php.net/manual/en/exception.construct.php Exception constructor}
     * @param Throwable|null $previous The previous exception used for the exception chaining. {@link http://php.net/manual/en/exception.construct.php Exception constructor}
     * @since 0.1
     */
    public function __construct(string $method = "", string $message = "", int $code = 0, Throwable $previous = null)
    {
        $this->algorithm = $method;
        parent::__construct($message, $code, $previous);
    }

    /**
     * Gets the algorithm that was not found.
     *
     * @return string Returns the algorithm that was not found.
     * @since 0.1
     */
    public function getAlgorithm() : string
    {
        return $this->algorithm;
    }

    /**
     * String representation of the exception.
     *
     * @return string Returns the string representation of the exception.
     * @since 0.1
     */
    public function __toString() : string
    {
        return sprintf("For hash algorithm '%s' %s", $this->algorithm, parent::__toString());
    }
}