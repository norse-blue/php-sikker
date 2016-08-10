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

namespace NorseBlue\Sikker\Asymmetric\Keys;

use InvalidArgumentException;

/**
 * Class CryptoKeyTypeException
 *
 * @package NorseBlue\Sikker\Asymmetric\Keys
 * @since 0.3
 * @codeCoverageIgnore This class does not need to be covered by tests.
 */
class CryptoKeyTypeException extends InvalidArgumentException
{
}