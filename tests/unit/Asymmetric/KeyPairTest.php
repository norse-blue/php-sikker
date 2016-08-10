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
use InvalidArgumentException;
use NorseBlue\Sikker\Asymmetric\Keys\KeyPair;
use NorseBlue\Sikker\Asymmetric\Keys\PrivateKey;
use NorseBlue\Sikker\Asymmetric\Keys\PublicKey;
use NorseBlue\Sikker\OpenSSL\OpenSSLNotAvailableException;

class KeyPairTest extends Unit
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
     * @var string The path to the DH Private Key example file.
     */
    const DH_PRIVATE_KEY_EXAMPLE_FILE = 'tests/_data/DH_private_key_example.pem';

    /**
     * @var string The path to the DH Public Key example file.
     */
    const DH_PUBLIC_KEY_EXAMPLE_FILE = 'tests/_data/DH_public_key_example.pem';

    /**
     * @var string The path to the EC Private Key example file.
     */
    const EC_PRIVATE_KEY_EXAMPLE_FILE = 'tests/_data/EC_private_key_example.pem';

    /**
     * @var string The path to the EC Public Key example file.
     */
    const EC_PUBLIC_KEY_EXAMPLE_FILE = 'tests/_data/EC_public_key_example.pem';

    /**
     * @var string Helper payload to hash.
     */
    const PAYLOAD = 'You know nothing Jon Snow! Winter is coming!';

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

    public function testFromPEM()
    {
        $this->specify('Loads an RSA KeyPair instance from the keys PEM strings.', function () {
            if (extension_loaded('openssl')) {
                $privateKeyContents = str_replace("\r", "",
                    trim(file_get_contents(self::RSA_PRIVATE_KEY_EXAMPLE_FILE)));
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::RSA_PUBLIC_KEY_EXAMPLE_FILE)));
                $keyPair = KeyPair::fromPEM($privateKeyContents, $publicKeyContents);
            }
        });

        $this->specify('Loads an DSA KeyPair instance from the keys PEM strings.', function () {
            if (extension_loaded('openssl')) {
                $privateKeyContents = str_replace("\r", "",
                    trim(file_get_contents(self::DSA_PRIVATE_KEY_EXAMPLE_FILE)));
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::DSA_PUBLIC_KEY_EXAMPLE_FILE)));
                $keyPair = KeyPair::fromPEM($privateKeyContents, $publicKeyContents);
            }
        });

        $this->specify('Loads an DH KeyPair instance from the keys PEM strings.', function () {
            if (extension_loaded('openssl')) {
                $privateKeyContents = str_replace("\r", "", trim(file_get_contents(self::DH_PRIVATE_KEY_EXAMPLE_FILE)));
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::DH_PUBLIC_KEY_EXAMPLE_FILE)));
                $keyPair = KeyPair::fromPEM($privateKeyContents, $publicKeyContents);
            }
        });

        $this->specify('Loads an EC KeyPair instance from the keys PEM strings.', function () {
            if (extension_loaded('openssl')) {
                $privateKeyContents = str_replace("\r", "", trim(file_get_contents(self::EC_PRIVATE_KEY_EXAMPLE_FILE)));
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::EC_PUBLIC_KEY_EXAMPLE_FILE)));
                $keyPair = KeyPair::fromPEM($privateKeyContents, $publicKeyContents);
            }
        });

        $this->specify('Detects key pairs that do not match.', function () {
            if (extension_loaded('openssl')) {
                $privateKeyContents = str_replace("\r", "",
                    trim(file_get_contents(self::RSA_PRIVATE_KEY_EXAMPLE_FILE)));
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::DSA_PUBLIC_KEY_EXAMPLE_FILE)));
                $this->expectException(InvalidArgumentException::class);
                $keyPair = KeyPair::fromPEM($privateKeyContents, $publicKeyContents);
            }
        });
    }

    /**
     * Tests private/public encrypt/decrypt
     */
    public function testEncryptDecrypt()
    {
        $this->specify('Encrypts and decrypts the message correctly.', function () {
            if (extension_loaded('openssl')) {
                $privateKey = PrivateKey::fromPEM(file_get_contents(self::RSA_PRIVATE_KEY_EXAMPLE_FILE));
                $publicKey = PublicKey::fromPEM(file_get_contents(self::RSA_PUBLIC_KEY_EXAMPLE_FILE));

                $privateEncrypted = $privateKey->encrypt(self::PAYLOAD);
                $this->assertEquals(self::PAYLOAD, $publicKey->decrypt($privateEncrypted));

                $publicEncrypted = $publicKey->encrypt(self::PAYLOAD);
                $this->assertEquals(self::PAYLOAD, $privateKey->decrypt($publicEncrypted));
            }
        });
    }

    /**
     * Tests private/public seal/unseal
     */
    public function testSealUnseal()
    {
        $this->specify('Seals and unseals the message correctly.', function () {
            if (extension_loaded('openssl')) {
                $privateKey = PrivateKey::fromPEM(file_get_contents(self::RSA_PRIVATE_KEY_EXAMPLE_FILE));
                $publicKey = PublicKey::fromPEM(file_get_contents(self::RSA_PUBLIC_KEY_EXAMPLE_FILE));

                $sealed = $publicKey->seal(self::PAYLOAD);
                $this->assertInternalType('array', $sealed);
                $this->assertEquals(3, count($sealed));
                $this->assertEquals(self::PAYLOAD, $privateKey->unseal($sealed[0], $sealed[1], $sealed[2]));
            }
        });
    }

    /**
     * Tests private/public sign/verify
     */
    public function testSignVerify()
    {
        $this->specify('Signs and verifies the message correctly.', function () {
            if (extension_loaded('openssl')) {
                $privateKey = PrivateKey::fromPEM(file_get_contents(self::RSA_PRIVATE_KEY_EXAMPLE_FILE));
                $publicKey = PublicKey::fromPEM(file_get_contents(self::RSA_PUBLIC_KEY_EXAMPLE_FILE));

                $signed = $privateKey->sign(self::PAYLOAD);
                $this->assertInternalType('array', $signed);
                $this->assertEquals(2, count($signed));
                $this->assertTrue($publicKey->verify(self::PAYLOAD, $signed[0], $signed[1]));
            }
        });
    }
}
