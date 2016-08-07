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
use NorseBlue\Sikker\Keys\PublicKey;
use NorseBlue\Sikker\OpenSSL\OpenSSL;
use NorseBlue\Sikker\OpenSSL\OpenSSLNotAvailableException;
use RuntimeException;

class CryptoKeySubclass extends CryptoKey
{
    public function decrypt(string $encryptedData) : string
    {
        return '';
    }

    public function encrypt(string $rawData) : string
    {
        return '';
    }

    public function getPEM(string $passphrase = null) : string
    {
        return '';
    }

    public function save(string $path, string $passphrase = null) : bool
    {
        return true;
    }
}

class CryptoKeyTest extends Unit
{
    use Specify;

    /**
     * @var string The path to the DSA Private Key example file.
     */
    const DSA_PRIVATE_KEY_EXAMPLE_FILE = 'tests/_data/DSA_private_key_example.pem';

    /**
     * @var string The path to the DSA Public Key example file.
     */
    const DSA_PUBLIC_KEY_EXAMPLE_FILE = 'tests/_data/DSA_public_key_example.pem';

    /**
     * @var string The path to the RSA Private Key example file.
     * @see http://phpseclib.sourceforge.net/rsa/examples.html phpseclib: RSA Examples and Notes
     */
    const RSA_PRIVATE_KEY_EXAMPLE_FILE = 'tests/_data/RSA_private_key_example.pem';

    /**
     * @var string The path to the RSA Public Key example file.
     * @see http://phpseclib.sourceforge.net/rsa/examples.html phpseclib: RSA Examples and Notes
     */
    const RSA_PUBLIC_KEY_EXAMPLE_FILE = 'tests/_data/RSA_public_key_example.pem';

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

    /**
     * Tests the getters functions.
     */
    public function testGetters()
    {
        $this->specify('Gets the RSA private key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $privateKeyContents = str_replace("\r", "",
                    trim(file_get_contents(self::RSA_PRIVATE_KEY_EXAMPLE_FILE)));
                $privateKey = PrivateKey::fromPEM($privateKeyContents);
                $this->assertInternalType('resource', $privateKey->getResource());
                $this->assertEquals(CryptoKey::DEFAULT_CONFIG, $privateKey->getConfig());
                $this->assertEquals(4, count($privateKey->getDetails()));
                $this->assertEquals(1024, $privateKey->getBits());
                $this->assertEquals(OpenSSL::KEYTYPE_RSA, $privateKey->getType());
                $this->assertEquals('rsa', $privateKey->getTypeAsString());
                $this->assertEquals('f0e293a34da5883dcfbffe35dad2699e6644373a', sha1($privateKey->getModulus()));
                $this->assertEquals($privateKeyContents, $privateKey->getPEM());
                $this->assertTrue($privateKey->isRSA());
                $this->assertFalse($privateKey->isDSA());
                $this->assertFalse($privateKey->isDH());
                $this->assertFalse($privateKey->isEC());
            }
        });

        $this->specify('Gets the RSA public key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::RSA_PUBLIC_KEY_EXAMPLE_FILE)));
                $publicKey = PublicKey::fromPEM($publicKeyContents);
                $this->assertInternalType('resource', $publicKey->getResource());
                $this->assertEquals(CryptoKey::DEFAULT_CONFIG, $publicKey->getConfig());
                $this->assertEquals(4, count($publicKey->getDetails()));
                $this->assertEquals(1024, $publicKey->getBits());
                $this->assertEquals(OpenSSL::KEYTYPE_RSA, $publicKey->getType());
                $this->assertEquals('rsa', $publicKey->getTypeAsString());
                $this->assertEquals('f0e293a34da5883dcfbffe35dad2699e6644373a', sha1($publicKey->getModulus()));
                $this->assertEquals($publicKeyContents, $publicKey->getPEM());
                $this->assertTrue($publicKey->isRSA());
                $this->assertFalse($publicKey->isDSA());
                $this->assertFalse($publicKey->isDH());
                $this->assertFalse($publicKey->isEC());
            }
        });

        $this->specify('Gets the DSA private key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $privateKeyContents = str_replace("\r", "",
                    trim(file_get_contents(self::DSA_PRIVATE_KEY_EXAMPLE_FILE)));
                $privateKey = PrivateKey::fromPEM($privateKeyContents);
                $this->assertInternalType('resource', $privateKey->getResource());
                $this->assertEquals(CryptoKey::DEFAULT_CONFIG, $privateKey->getConfig());
                $this->assertEquals(4, count($privateKey->getDetails()));
                $this->assertEquals(1024, $privateKey->getBits());
                $this->assertEquals(OpenSSL::KEYTYPE_DSA, $privateKey->getType());
                $this->assertEquals('dsa', $privateKey->getTypeAsString());
                $this->assertEquals('8196c7dd65b518f9e555fb3683f8d0b68a8edbf2', sha1($privateKey->getModulus()));
                $this->assertEquals($privateKeyContents, $privateKey->getPEM());
                $this->assertTrue($privateKey->isDSA());
                $this->assertFalse($privateKey->isRSA());
                $this->assertFalse($privateKey->isDH());
                $this->assertFalse($privateKey->isEC());
            }
        });

        $this->specify('Gets the DSA public key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::DSA_PUBLIC_KEY_EXAMPLE_FILE)));
                $publicKey = PublicKey::fromPEM($publicKeyContents);
                $this->assertInternalType('resource', $publicKey->getResource());
                $this->assertEquals(CryptoKey::DEFAULT_CONFIG, $publicKey->getConfig());
                $this->assertEquals(4, count($publicKey->getDetails()));
                $this->assertEquals(1024, $publicKey->getBits());
                $this->assertEquals(OpenSSL::KEYTYPE_DSA, $publicKey->getType());
                $this->assertEquals('dsa', $publicKey->getTypeAsString());
                $this->assertEquals('8196c7dd65b518f9e555fb3683f8d0b68a8edbf2', sha1($publicKey->getModulus()));
                $this->assertEquals($publicKeyContents, $publicKey->getPEM());
                $this->assertTrue($publicKey->isDSA());
                $this->assertFalse($publicKey->isRSA());
                $this->assertFalse($publicKey->isDH());
                $this->assertFalse($publicKey->isEC());
            }
        });
    }

    /**
     * Tests the save function.
     */
    public function testSave()
    {
        $this->specify('Saves the private key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                @unlink(self::SAVE_FILE_PATH);
                $this->assertFalse(file_exists(self::SAVE_FILE_PATH));
                $privateKeyContents = str_replace("\r", "",
                    trim(file_get_contents(self::RSA_PRIVATE_KEY_EXAMPLE_FILE)));
                $privateKey = PrivateKey::fromPEM($privateKeyContents);
                $privateKey->save(self::SAVE_FILE_PATH);
                $this->assertTrue(file_exists(self::SAVE_FILE_PATH));
                $this->assertEquals($privateKeyContents,
                    str_replace("\r", "", trim(file_get_contents(self::SAVE_FILE_PATH))));
                @unlink(self::SAVE_FILE_PATH);
            }
        });

        $this->specify('Saves the public key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                @unlink(self::SAVE_FILE_PATH);
                $this->assertFalse(file_exists(self::SAVE_FILE_PATH));
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::RSA_PUBLIC_KEY_EXAMPLE_FILE)));
                $publicKey = PublicKey::fromPEM($publicKeyContents);
                $publicKey->save(self::SAVE_FILE_PATH);
                $this->assertTrue(file_exists(self::SAVE_FILE_PATH));
                $this->assertEquals($publicKeyContents, file_get_contents(self::SAVE_FILE_PATH));
                @unlink(self::SAVE_FILE_PATH);
            }
        });
    }
}
