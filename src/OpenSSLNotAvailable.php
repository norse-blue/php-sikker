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

namespace NorseBlue\Sikker;

use RuntimeException;

/**
 * Class OpenSSLNotAvailable
 *
 * @package NorseBlue\Sikker
 * @see http://php.net/manual/en/class.runtimeexception.php
 * @since 0.3
 * @codeCoverageIgnore This class does not need to be covered by tests.
 */
class OpenSSLNotAvailable extends RuntimeException
{
}