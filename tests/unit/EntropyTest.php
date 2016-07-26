<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.1.1
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Tests;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\Entropy;

class EntropyTest extends Unit
{
    use Specify;

    protected function _after()
    {
    }

    protected function _before()
    {
    }

    // tests

    /**
     * Tests the repeatability factor calculation.
     */
    public function testCalculateRepeatabilityFactor()
    {
        $this->specify('Calculates the char repeatability factor on the given token.', function () {
            $token = 'CnRwh61ygUUEAs8o2JphrOGrfZ8sxSLr';
            $repeatabilityFactor = 0.1875;      //  6(repeats) / 32(length)
            $this->assertEquals($repeatabilityFactor, Entropy::calculateRepeatFactor($token));
        });
    }
}