<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3.5
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Asymmetric\Keys;

use InvalidArgumentException;
use NorseBlue\Sikker\Asymmetric\SignatureAlgorithm;
use NorseBlue\Sikker\OpenSSL\OpenSSL;
use NorseBlue\Sikker\OpenSSL\OpenSSLException;
use NorseBlue\Sikker\Symmetric\CipherMethod;
use NorseBlue\Sikker\Symmetric\CipherMethodNotAvailableException;
use NorseBlue\Sikker\Symmetric\InitVector;

/**
 * Class PublicKey
 *
 * @package NorseBlue\Sikker\Asymmetric\Keys
 * @since 0.3
 */
class PublicKey extends CryptoKey
{
    /**
     * Creates a PublicKey from the key's string in PEM format.
     *
     * @param string $key The private key string in PEM format.
     * @return PublicKey The PrivateKey object.
     * @since 0.3
     */
    public static function fromPEM(string $key) : PublicKey
    {
        OpenSSL::resetErrors();
        if (($resource = openssl_pkey_get_public($key)) === false) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'Cannot read the given public key.');
            // @codeCoverageIgnoreEnd
        }

        return new self($resource);
    }

    /**
     * Decrypts the given data.
     *
     * @param string $encryptedData The data to decrypt.
     * @return string Returns the decrypted data.
     * @throws OpenSSLException when the given data cannot be decrypted.
     * @since 0.3
     */
    public function decrypt(string $encryptedData) : string
    {
        OpenSSL::resetErrors();
        if (openssl_public_decrypt($encryptedData, $decrypted, $this->resource) === false) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'Could not decrypt the given data with this public key.');
            // @codeCoverageIgnoreEnd
        }

        return $decrypted;
    }

    /**
     * Encrypts the given data.
     *
     * @param string $rawData The data to encrypt.
     * @return string Returns the encrypted data.
     * @throws OpenSSLException when the given data cannot be encrypted.
     * @since 0.3
     */
    public function encrypt(string $rawData) : string
    {
        OpenSSL::resetErrors();
        if (openssl_public_encrypt($rawData, $encrypted, $this->resource) === false) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'Could not encrypt the given data with this public key.');
            // @codeCoverageIgnoreEnd
        }

        return $encrypted;
    }

    /**
     * Gets the public key string in PEM format.
     *
     * @param string $passphrase This param is ignored.
     * @return null|string Returns the public key string in PEM format.
     * @since 0.3
     */
    public function getPEM(string $passphrase = null) : string
    {
        return trim($this->details['key']);
    }

    /**
     * Verifies if the given key matches is a pair match.
     *
     * @param CryptoKey $pairedKey The paired key to test.
     * @return bool Returns true when the given paired key matches, false otherwise.
     * @throws InvalidArgumentException when the given paired key is not an instance of PrivateKey.
     * @since 0.3
     */
    public function isPairOf(CryptoKey $pairedKey) : bool
    {
        if (!$pairedKey instanceof PrivateKey) {
            throw new InvalidArgumentException('The paired key must be an instance of PrivateKey.');
        }

        if (($type = $this->getType()) !== $pairedKey->getType()) {
            return false;
        }

        if ($type === CryptoKeyType::EC) {
            return $pairedKey->getPublicKeyPEM() == $this->getPEM();
        } else {
            return $this->getModulus() == $pairedKey->getModulus();
        }
    }

    /**
     * Saves the public key to a file.
     *
     * @param string $path The path of the file to save.
     * @param string|null $passphrase This param is ignored.
     * @return bool Returns true on success, false otherwise.
     * @since 0.3
     */
    public function save(string $path, string $passphrase = null) : bool
    {
        $pem = $this->getPEM($passphrase);
        return !is_bool(file_put_contents($path, $pem));
    }

    /**
     * Verifies the given signature for the message.
     *
     * @param string $message The message that was signed.
     * @param string $signature The signature generated with a private key for the message.
     * @param int $signatureAlgorithm The signature algorithm used.
     * @return bool Returns true if the signature is verified, false otherwise.
     * @throws OpenSSLException when an error occurs while verifying the signature.
     * @since 0.3
     */
    public function verify(
        string $message,
        string $signature,
        int $signatureAlgorithm = SignatureAlgorithm::SHA1
    ) : bool {
        OpenSSL::resetErrors();
        if (($verified = openssl_verify($message, $signature, $this->resource, $signatureAlgorithm)) === -1) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'An error occurred while verifying signature.');
            // @codeCoverageIgnoreEnd
        }

        return ($verified === 1);
    }

    /**
     * Seals the given message in an encrypted envelope that can only be decrypted by the private key matching the public key.
     *
     * @param string $message The message to be sealed.
     * @param string $cipherMethod The cipher method to use from CipherMethod.
     * @param string $iv The optional initialization vector for some cipher methods.
     * @return array Returns an array containing the envelope along other information like the key and method used.
     *                  0 => [string] envelope
     * 1 => [string] envelope key
     * 2 => [string] cipher method used
     * @since 0.3
     */
    public function seal(string $message, string $cipherMethod = CipherMethod::RC4, string $iv = '') : array
    {
        OpenSSL::resetErrors();
        if (!CipherMethod::isAvailable($cipherMethod)) {
            throw new CipherMethodNotAvailableException($cipherMethod,
                'The given cipher method is not available in the current platform stack.');
        }

        $paddedIV = InitVector::pad($iv);
        if (@openssl_seal($message, $envelope, $envelopeKeys, [$this->resource], $cipherMethod, $paddedIV) === false) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'Could not seal message.');
            // @codeCoverageIgnoreEnd
        }

        return [$envelope, $envelopeKeys[0], $cipherMethod];
    }
}