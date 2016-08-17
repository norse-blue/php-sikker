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

namespace NorseBlue\Sikker\Tests\Asymmetric;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\Symmetric\CipherMode;

class CipherModeTest extends Unit
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
     * Tests conversions
     */
    public function testConversion()
    {
        $this->specify('Converts the values to names correctly.', function () {
            $this->assertEquals('ecb', CipherMode::asString(CipherMode::ECB));
            $this->assertEquals('cbc', CipherMode::asString(CipherMode::CBC));
            $this->assertEquals('unknown', CipherMode::asString(CipherMode::UNKNOWN));
            $this->assertEquals('unknown', CipherMode::asString(998));
        });

        $this->specify('Converts the values from names correctly.', function () {
            $this->assertEquals(CipherMode::ECB, CipherMode::asValue('ecb'));
            $this->assertEquals(CipherMode::CBC, CipherMode::asValue('cbc'));
            $this->assertEquals(CipherMode::UNKNOWN, CipherMode::asValue('unknown'));
            $this->assertEquals(CipherMode::UNKNOWN, CipherMode::asValue('not existent key'));
        });
    }
}
