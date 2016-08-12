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
use NorseBlue\Sikker\Symmetric\CipherBlockSize;

class CipherBlockSizeTest extends Unit
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
            $this->assertEquals('128', CipherBlockSize::toName(CipherBlockSize::_128));
            $this->assertEquals('192', CipherBlockSize::toName(CipherBlockSize::_192));
            $this->assertEquals('256', CipherBlockSize::toName(CipherBlockSize::_256));
            $this->assertEquals('unknown', CipherBlockSize::toName(CipherBlockSize::UNKNOWN));
            $this->assertEquals('unknown', CipherBlockSize::toName(998));
        });

        $this->specify('Converts the values from names correctly.', function () {
            $this->assertEquals(CipherBlockSize::_128, CipherBlockSize::fromName('128'));
            $this->assertEquals(CipherBlockSize::_192, CipherBlockSize::fromName('192'));
            $this->assertEquals(CipherBlockSize::_256, CipherBlockSize::fromName('256'));
            $this->assertEquals(CipherBlockSize::UNKNOWN, CipherBlockSize::fromName('unknown'));
            $this->assertEquals(CipherBlockSize::UNKNOWN, CipherBlockSize::fromName('not existent key'));
        });
    }
}
