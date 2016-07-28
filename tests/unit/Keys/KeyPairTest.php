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

namespace NorseBlue\Sikker\Tests\Keys;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\Keys\KeyPair;
use NorseBlue\Sikker\Keys\PrivateKey;
use NorseBlue\Sikker\Keys\PublicKey;
use NorseBlue\Sikker\OpenSSL\OpenSSLNotAvailableException;

class KeyPairTest extends Unit
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
     * Tests the generate function.
     */
    public function testGenerate()
    {
        $this->specify('Generates a KeyPair correctly.', function () {
            if (extension_loaded('openssl')) {
                $keyPair = KeyPair::generate();
                $this->assertInstanceOf(PrivateKey::class, $keyPair->getPrivateKey());
                $this->assertInstanceOf(PublicKey::class, $keyPair->getPublicKey());
            } else {
                $this->expectException(OpenSSLNotAvailableException::class);
                $keyPair = KeyPair::generate();
            }
        });
    }
}
