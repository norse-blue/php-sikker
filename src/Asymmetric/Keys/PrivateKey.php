<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3
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
use NorseBlue\Sikker\Symmetric\InitVector;

/**
 * Class PrivateKey
 *
 * @package NorseBlue\Sikker\Asymmetric\Keys
 * @since 0.3
 */
class PrivateKey extends CryptoKey
{
    /**
     * Creates a PrivateKey from the key's string in PEM format.
     *
     * @param string $key The private key string in PEM format.
     * @param string $passphrase The passphrase if exists.
     * @return PrivateKey The PrivateKey object.
     * @throws OpenSSLException when the given private key cannot be read.
     * @since 0.3
     */
    public static function fromPEM(string $key, string $passphrase = '') : PrivateKey
    {
        OpenSSL::resetErrors();
        if (($resource = openssl_pkey_get_private($key, $passphrase)) === false) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'Cannot read the given private key.');
            // @codeCoverageIgnoreEnd
        }

        return new self($resource);
    }

    /**
     * Gets the matching public key in PEM format.
     *
     * @return string Returns the matching public key in PEM format.
     * @since 0.3
     */
    public function getPublicKeyPEM() : string
    {
        return trim($this->details['key']);
    }

    /**
     * Decrypts the given data.
     *
     * @param string $encryptedData The data to decrypt.
     * @throws OpenSSLException when the given data cannot be decrypted.
     * @return string Returns the decrypted data.
     */
    public function decrypt(string $encryptedData) : string
    {
        OpenSSL::resetErrors();
        if (openssl_private_decrypt($encryptedData, $decrypted, $this->resource) === false) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'Could not decrypt the given data with this private key.');
            // @codeCoverageIgnoreEnd
        }

        return (string) $decrypted;
    }

    /**
     * Encrypts the given data.
     *
     * @param string $rawData The data to encrypt.
     * @throws OpenSSLException when the given data cannot be encrypted.
     * @return string Returns the encrypted data.
     */
    public function encrypt(string $rawData) : string
    {
        OpenSSL::resetErrors();
        if (openssl_private_encrypt($rawData, $encrypted, $this->resource) === false) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'Could not encrypt the given data with this private key.');
            // @codeCoverageIgnoreEnd
        }

        return (string) $encrypted;
    }

    /**
     * Gets the private key string in PEM format.
     *
     * @param string $passphrase The optional passphrase to protect the private key.
     * @return null|string Returns the private key string in PEM format.
     * @throws OpenSSLException when the key's PEM string cannot be gathered.
     * @since 0.3
     */
    public function getPEM(string $passphrase = null) : string
    {
        OpenSSL::resetErrors();
        if (openssl_pkey_export($this->resource, $key, $passphrase, $this->config) === false) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'Could not get private key PEM.');
            // @codeCoverageIgnoreEnd
        }

        return trim($key);
    }

    /**
     * Verifies if the given key matches is a pair match.
     *
     * @param CryptoKey $pairedKey The paired key to test.
     * @return bool Returns true when the given paired key matches, false otherwise.
     * @throws InvalidArgumentException when the given paired key is not an instance of PublicKey.
     * @since 0.3
     */
    public function isPairOf(CryptoKey $pairedKey) : bool
    {
        if (!$pairedKey instanceof PublicKey) {
            throw new InvalidArgumentException('The paired key must be an instance of PublicKey.');
        }

        if (($type = $this->getType()) !== $pairedKey->getType()) {
            return false;
        }

        if ($type === CryptoKeyType::EC) {
            return $this->getPublicKeyPEM() == $pairedKey->getPEM();
        } else {
            return $this->getModulus() == $pairedKey->getModulus();
        }
    }

    /**
     * Saves the private key to a file.
     *
     * @param string $path The path of the file to save.
     * @param string|null $passphrase The optional passphrase to secure the private key.
     * @return bool Returns true on success, false otherwise.
     * @since 0.3
     */
    public function save(string $path, string $passphrase = null) : bool
    {
        OpenSSL::resetErrors();
        return openssl_pkey_export_to_file($this->resource, $path, $passphrase, $this->config);
    }

    /**
     * Signs the message with the PrivateKey.
     *
     * @param string $message The message to be signed.
     * @param int $signatureAlgorithm The signature algorithm to be used.
     * @return array Returns an array with the signature along other information.
     *                  0 => [string] signature
     *                  1 => [int] signature algorithm used
     * @throws OpenSSLException when the message cannot be signed.
     * @since 0.3
     */
    public function sign(string $message, int $signatureAlgorithm = SignatureAlgorithm::SHA1) : array
    {
        OpenSSL::resetErrors();
        if (openssl_sign($message, $signature, $this->resource, $signatureAlgorithm) === false) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'Could not sign message.');
            // @codeCoverageIgnoreEnd
        }

        return [$signature, $signatureAlgorithm];
    }

    /**
     * Unseals the given envelope.
     *
     * @param string $envelope The envelope to unseal.
     * @param string $envelopeKey The envelope hash key.
     * @param string $cipherMethod The cipher method used to seal the message.
     * @param string $iv The optional initialization vector for some cipher methods.
     * @return string The unsealed message.
     * @since 0.3
     */
    public function unseal(string $envelope, string $envelopeKey, string $cipherMethod = null, string $iv = '') : string
    {
        OpenSSL::resetErrors();
        $paddedIV = InitVector::pad($iv);
        if (@openssl_open($envelope, $message, $envelopeKey, $this->resource, $cipherMethod, $paddedIV) === false
        ) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'Could not unseal envelope.');
            // @codeCoverageIgnoreEnd
        }

        return $message;
    }
}