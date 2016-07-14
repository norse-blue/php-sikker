<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.1
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker;

use RuntimeException;
use Throwable;

/**
 * Class FileNotFoundException
 *
 * @package NorseBlue\Sikker\Hash
 * @see http://php.net/manual/en/class.runtimeexception.php
 * @since 0.1
 * @codeCoverageIgnore This class does not need to be covered by tests. It's just an extension to exceptions with a property and it's getter.
 */
class FileNotFoundException extends RuntimeException
{
    /**
     * @var string The file that was not found.
     */
    protected $notFoundFile;

    /**
     * FileNotFoundException constructor.
     *
     * @param string $notFoundFile The file that was not found.
     * @param string $message The Exception message to throw. {@link http://php.net/manual/en/exception.construct.php Exception constructor}
     * @param int $code The Exception code. {@link http://php.net/manual/en/exception.construct.php Exception constructor}
     * @param Throwable|null $previous The previous exception used for the exception chaining. {@link http://php.net/manual/en/exception.construct.php Exception constructor}
     * @since 0.1
     */
    public function __construct(string $notFoundFile = "", string $message = "", int $code = 0, Throwable $previous = null)
    {
        $this->notFoundFile = $notFoundFile;
        parent::__construct($message, $code, $previous);
    }

    /**
     * Gets the file that was not found.
     *
     * @return string Returns the file that was not found.
     * @since 0.1
     */
    public function getNotFoundFile()
    {
        return $this->notFoundFile;
    }

    /**
     * String representation of the exception.
     *
     * @return string Returns the string representation of the exception.
     * @since 0.1
     */
    public function __toString()
    {
        return sprintf("For file '%s' %s", $this->notFoundFile, parent::__toString());
    }
}