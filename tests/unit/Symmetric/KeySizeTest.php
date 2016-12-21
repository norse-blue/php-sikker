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

namespace NorseBlue\Sikker\Tests\Asymmetric;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\Symmetric\KeySize;

class KeySizeTest extends Unit
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
     * Tests the type names
     */
    public function testTypeNames()
    {
        $this->specify('Converts the values to names correctly.', function () {
            $this->assertEquals('40 bit', KeySize::asString(KeySize::_40));
            $this->assertEquals('64 bit', KeySize::asString(KeySize::_64));
            $this->assertEquals('128 bit', KeySize::asString(KeySize::_128));
            $this->assertEquals('192 bit', KeySize::asString(KeySize::_192));
            $this->assertEquals('256 bit', KeySize::asString(KeySize::_256));
            $this->assertEquals('unknown', KeySize::asString(KeySize::UNKNOWN));
            $this->assertEquals('unknown', KeySize::asString(998));
        });

        $this->specify('Converts the values from names correctly.', function () {
            $this->assertEquals(KeySize::_40, KeySize::asValue('40'));
            $this->assertEquals(KeySize::_64, KeySize::asValue('64'));
            $this->assertEquals(KeySize::_128, KeySize::asValue('128'));
            $this->assertEquals(KeySize::_192, KeySize::asValue('192'));
            $this->assertEquals(KeySize::_256, KeySize::asValue('256'));
            $this->assertEquals(KeySize::_40, KeySize::asValue('40 bit'));
            $this->assertEquals(KeySize::_64, KeySize::asValue('64 bit'));
            $this->assertEquals(KeySize::_128, KeySize::asValue('128 bit'));
            $this->assertEquals(KeySize::_192, KeySize::asValue('192 bit'));
            $this->assertEquals(KeySize::_256, KeySize::asValue('256 bit'));
            $this->assertEquals(KeySize::UNKNOWN, KeySize::asValue('unknown'));
            $this->assertEquals(KeySize::UNKNOWN, KeySize::asValue('not existent key'));
        });
    }
}
