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
use NorseBlue\Sikker\Keys\CryptoKey;
use NorseBlue\Sikker\Keys\PrivateKey;
use NorseBlue\Sikker\OpenSSL\OpenSSLNotAvailableException;
use RuntimeException;

class CryptoKeySubclass extends CryptoKey
{
}

class CryptoKeyTest extends Unit
{
    use Specify;

    /**
     * @var string The path to the Private Key example file.
     * @see http://phpseclib.sourceforge.net/rsa/examples.html phpseclib: RSA Examples and Notes
     */
    const PRIVATE_KEY_EXAMPLE_FILE = 'tests/_data/private_key_example.pem';

    /**
     * @var string The path to the Public Key example file.
     * @see http://phpseclib.sourceforge.net/rsa/examples.html phpseclib: RSA Examples and Notes
     */
    const PUBLIC_KEY_EXAMPLE_FILE = 'tests/_data/public_key_example.pem';

    /**
     * @var string The path to a temp file to be saved.
     */
    const SAVE_FILE_PATH = 'tests/_temp/cryptokey_example.pem';

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
    public function testConstructor()
    {
        $this->specify('Throws an RuntimeException if the passed value is not a resource when constructing the object.',
            function () {
                if (extension_loaded('openssl')) {
                    $this->expectException(RuntimeException::class);
                    $key = new CryptoKeySubclass(998);
                } else {
                    $this->expectException(OpenSSLNotAvailableException::class);
                    $key = new CryptoKeySubclass(998);
                }
            });
    }

    public function testGetResourceAndGetPEM()
    {
        $this->specify('Gets the private key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $privateKeyContents = str_replace("\r", "", trim(file_get_contents(self::PRIVATE_KEY_EXAMPLE_FILE)));
                $privateKey = PrivateKey::fromPEM($privateKeyContents);
                $this->assertInternalType('resource', $privateKey->getResource());
                $this->assertEquals($privateKeyContents, $privateKey->getPEM());
            }
        });
        /*
                $this->specify('Gets the public key in PEM format.', function () {
                    if (extension_loaded('openssl')) {
                        $publicKeyContents = file_get_contents(self::PUBLIC_KEY_EXAMPLE_FILE);
                        $publicKey = PublicKey::fromPEM($publicKeyContents);
                        $this->assertInternalType('resource', $publicKey->getResource());
                        $this->assertEquals($publicKeyContents, $publicKey->getPEM());
                    }
                });
        */
    }

    public function testSave()
    {
        $this->specify('Saves the private key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                @unlink(self::SAVE_FILE_PATH);
                $this->assertFalse(file_exists(self::SAVE_FILE_PATH));
                $privateKeyContents = str_replace("\r", "", trim(file_get_contents(self::PRIVATE_KEY_EXAMPLE_FILE)));
                $privateKey = PrivateKey::fromPEM($privateKeyContents);
                $privateKey->save(self::SAVE_FILE_PATH);
                $this->assertTrue(file_exists(self::SAVE_FILE_PATH));
                $this->assertEquals($privateKeyContents,
                    str_replace("\r", "", trim(file_get_contents(self::SAVE_FILE_PATH))));
                @unlink(self::SAVE_FILE_PATH);
            }
        });
        /*
                $this->specify('Saves the public key in PEM format.', function () {
                    if (extension_loaded('openssl')) {
                        @unlink(self::SAVE_FILE_PATH);
                        $this->assertFalse(file_exists(self::SAVE_FILE_PATH));
                        $publicKeyContents = file_get_contents(self::PUBLIC_KEY_EXAMPLE_FILE);
                        $publicKey = PublicKey::fromPEM($publicKeyContents);
                        $publicKey->save(self::SAVE_FILE_PATH);
                        $this->assertTrue(file_exists(self::SAVE_FILE_PATH));
                        $this->assertEquals($publicKeyContents, file_get_contents(self::SAVE_FILE_PATH));
                        @unlink(self::SAVE_FILE_PATH);
                    }
                });
        */
    }
}
