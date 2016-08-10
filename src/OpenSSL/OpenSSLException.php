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

namespace NorseBlue\Sikker\OpenSSL;

use RuntimeException;
use Throwable;

/**
 * Class OpenSSLException
 *
 * @package NorseBlue\Sikker
 * @see http://php.net/manual/en/class.runtimeexception.php
 * @since 0.3
 * @codeCoverageIgnore This class does not need to be covered by tests.
 */
class OpenSSLException extends RuntimeException
{
    /**
     * @var array The OpenSSL errors.
     */
    protected $errors;

    /**
     * OpenSSLException constructor.
     *
     * @param array $errors The OpenSSL errors.
     * @param string $message The Exception message to throw. {@link http://php.net/manual/en/exception.construct.php Exception constructor}
     * @param int $code The Exception code. {@link http://php.net/manual/en/exception.construct.php Exception constructor}
     * @param Throwable|null $previous The previous exception used for the exception chaining. {@link http://php.net/manual/en/exception.construct.php Exception constructor}
     * @since 0.3
     */
    public function __construct(array $errors, string $message = "", int $code = 0, Throwable $previous = null)
    {
        $this->errors = $errors;
        parent::__construct($message, $code, $previous);
    }

    /**
     * Gets the OpenSSL errors.
     *
     * @return array Returns the OpenSSL errors.
     * @since 0.3
     */
    public function getErrors() : array
    {
        return $this->errors;
    }

    /**
     * String representation of the exception.
     *
     * @return string Returns the string representation of the exception.
     * @since 0.3
     */
    public function __toString() : string
    {
        return sprintf("%s\nOpenSSL Errors:%s", parent::__toString(), implode("\n  - ", $this->errors));
    }
}