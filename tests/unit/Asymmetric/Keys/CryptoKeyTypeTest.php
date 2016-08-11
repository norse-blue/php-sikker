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

namespace NorseBlue\Sikker\Tests\Asymmetric\Keys;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\Asymmetric\Keys\CryptoKeyType;

class CryptoKeyTypeTest extends Unit
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
        $this->specify('Converts the key types to name correctly.', function () {
            $this->assertEquals('rsa', CryptoKeyType::toName(CryptoKeyType::RSA));
            $this->assertEquals('dsa', CryptoKeyType::toName(CryptoKeyType::DSA));
            $this->assertEquals('dh', CryptoKeyType::toName(CryptoKeyType::DH));
            $this->assertEquals('ec', CryptoKeyType::toName(CryptoKeyType::EC));
            $this->assertEquals('unknown', CryptoKeyType::toName(CryptoKeyType::UNKNOWN));
            $this->assertEquals('unknown', CryptoKeyType::toName(998));
        });

        $this->specify('Converts the key types from name correctly.', function () {
            $this->assertEquals(CryptoKeyType::RSA, CryptoKeyType::fromName('rsa'));
            $this->assertEquals(CryptoKeyType::DSA, CryptoKeyType::fromName('dsa'));
            $this->assertEquals(CryptoKeyType::DH, CryptoKeyType::fromName('dh'));
            $this->assertEquals(CryptoKeyType::EC, CryptoKeyType::fromName('ec'));
            $this->assertEquals(CryptoKeyType::UNKNOWN, CryptoKeyType::fromName('unknown'));
            $this->assertEquals(CryptoKeyType::UNKNOWN, CryptoKeyType::fromName('not existent key'));
        });
    }
}
