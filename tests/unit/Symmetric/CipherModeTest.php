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
            $this->assertEquals('ebc', CipherMode::toName(CipherMode::EBC));
            $this->assertEquals('cbc', CipherMode::toName(CipherMode::CBC));
            $this->assertEquals('unknown', CipherMode::toName(CipherMode::UNKNOWN));
            $this->assertEquals('unknown', CipherMode::toName(998));
        });

        $this->specify('Converts the values from names correctly.', function () {
            $this->assertEquals(CipherMode::EBC, CipherMode::fromName('ebc'));
            $this->assertEquals(CipherMode::CBC, CipherMode::fromName('cbc'));
            $this->assertEquals(CipherMode::UNKNOWN, CipherMode::fromName('unknown'));
            $this->assertEquals(CipherMode::UNKNOWN, CipherMode::fromName('not existent key'));
        });
    }
}
