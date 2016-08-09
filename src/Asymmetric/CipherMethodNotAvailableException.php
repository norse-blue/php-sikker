<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.2
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Asymmetric;

use RuntimeException;
use Throwable;

/**
 * Class CipherMethodNotAvailableException
 *
 * @package NorseBlue\Sikker\Asymmetric
 * @see http://php.net/manual/en/class.runtimeexception.php The RuntimeException class
 * @since 0.3
 * @codeCoverageIgnore This class does not need to be covered by tests. It's just an extension to exceptions with an additional property and it's getter.
 */
class CipherMethodNotAvailableException extends RuntimeException
{
    /**
     * @var string The method that was not found.
     */
    protected $method;

    /**
     * CipherMethodNotAvailableException constructor.
     *
     * @param string $method The method that was not found.
     * @param string $message The Exception message to throw. {@link http://php.net/manual/en/exception.construct.php Exception constructor}
     * @param int $code The Exception code. {@link http://php.net/manual/en/exception.construct.php Exception constructor}
     * @param Throwable|null $previous The previous exception used for the exception chaining. {@link http://php.net/manual/en/exception.construct.php Exception constructor}
     * @since 0.1
     */
    public function __construct(string $method = "", string $message = "", int $code = 0, Throwable $previous = null)
    {
        $this->method = $method;
        parent::__construct($message, $code, $previous);
    }

    /**
     * Gets the method that was not found.
     *
     * @return string Returns the method that was not found.
     * @since 0.1
     */
    public function getMethod() : string
    {
        return $this->method;
    }

    /**
     * String representation of the exception.
     *
     * @return string Returns the string representation of the exception.
     * @since 0.1
     */
    public function __toString() : string
    {
        return sprintf("For cipher method '%s' %s", $this->method, parent::__toString());
    }
}