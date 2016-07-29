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

namespace NorseBlue\Sikker\Certificates;

/**
 * Class Principal
 *
 * @package NorseBlue\Sikker\Certificates
 * @see https://en.wikipedia.org/wiki/Certificate_signing_request Certificate signing request
 * @since 0.3
 */
class Principal
{
    /**
     * @var string The country property key.
     */
    const PROPERTY_KEY_COUNTRY = 'C';

    /**
     * @var string The state or province property key.
     */
    const PROPERTY_KEY_STATE = 'ST';

    /**
     * @var string The locality property key.
     */
    const PROPERTY_KEY_LOCALITY = 'L';

    /**
     * @var string The organization property key.
     */
    const PROPERTY_KEY_ORGANIZATION = 'O';

    /**
     * @var string The organizational unit property key.
     */
    const PROPERTY_KEY_ORGANIZATIONAL_UNIT = 'OU';

    /**
     * @var string The common name property key.
     */
    const PROPERTY_KEY_COMMON_NAME = 'CN';

    /**
     * @var string The email property key.
     */
    const PROPERTY_KEY_EMAIL = 'EMAIL';

    /**
     * @var string The two-letter ISO code for the country where your organization is located e.g. GB, FR or US etc.
     */
    protected $countryName;
    /**
     * @var string This should not be abbreviated e.g. Sussex, Normandy, New Jersey
     */
    protected $stateOrProvinceName;
    /**
     * @var string e.g. London, Waterford, Paris, New York, Dhaka, Kochi
     */
    protected $localityName;
    /**
     * @var string Usually the legal incorporated name of a company and should include any suffixes such as Ltd., Inc., or Corp.
     */
    protected $organizationName;
    /**
     * @var string e.g. HR, Finance, IT
     */
    protected $organizationalUnitName;
    /**
     * @var string This is fully qualified domain name that you wish to secure e.g. 'www.example.com’ or 'mail.example.com'. This includes the Common Name (CN) e.g. 'www' or 'mail'
     */
    protected $commonName;
    /**
     * @var string An email address to contact the organization. Usually the email address of the certificate administrator or IT department
     */
    protected $emailAddress;

    /**
     * Principal constructor.
     *
     * @param string $countryName The two-letter ISO code for the country where your organization is located e.g. GB, FR or US etc.
     * @param string $stateOrProvinceName This should not be abbreviated e.g. Sussex, Normandy, New Jersey
     * @param string $localityName e.g. London, Waterford, Paris, New York, Dhaka, Kochi
     * @param string $organizationName Usually the legal incorporated name of a company and should include any suffixes such as Ltd., Inc., or Corp.
     * @param string $organizationalUnitName e.g. HR, Finance, IT
     * @param string $commonName This is fully qualified domain name that you wish to secure e.g. 'www.example.com’ or 'mail.example.com'. This includes the Common Name (CN) e.g. 'www' or 'mail'
     * @param string $emailAddress An email address to contact the organization. Usually the email address of the certificate administrator or IT department
     * @since 0.3
     */
    public function __construct(
        string $countryName = '',
        string $stateOrProvinceName = '',
        string $localityName = '',
        string $organizationName = '',
        string $organizationalUnitName = '',
        string $commonName = '',
        string $emailAddress = ''
    ) {
        $this->setCountryName($countryName);
        $this->setStateOrProvinceName($stateOrProvinceName);
        $this->setLocalityName($localityName);
        $this->setOrganizationName($organizationName);
        $this->setOrganizationalUnitName($organizationalUnitName);
        $this->setCommonName($commonName);
        $this->setEmailAddress($emailAddress);
    }

    /**
     * Gets a Principal from an array.
     *
     * @param array $info The Principal information.
     * @return Principal Return a Principal from the given information.
     * @since 0.3
     */
    public static function fromArray(array $info)
    {
        return new Principal($info[self::PROPERTY_KEY_COUNTRY]??'', $info[self::PROPERTY_KEY_STATE]??'',
            $info[self::PROPERTY_KEY_LOCALITY]??'', $info[self::PROPERTY_KEY_ORGANIZATION]??'',
            $info[self::PROPERTY_KEY_ORGANIZATIONAL_UNIT]??'', $info[self::PROPERTY_KEY_COMMON_NAME]??'',
            $info[self::PROPERTY_KEY_EMAIL]??'');
    }

    /**
     * Gets the country name.
     *
     * @return string Returns the country name.
     * @since 0.3
     */
    public function getCountryName() : string
    {
        return $this->countryName;
    }

    /**
     * Sets the country name.
     *
     * @param string $countryName The country name.
     * @return Principal Returns this instance for fluent interface.
     * @since 0.3
     */
    public function setCountryName(string $countryName) : Principal
    {
        $this->countryName = $countryName;
        return $this;
    }

    /**
     * Gets the state or province name.
     *
     * @return string Returns the state or province name.
     * @since 0.3
     */
    public function getStateOrProvinceName() : string
    {
        return $this->stateOrProvinceName;
    }

    /**
     * Sets the state or province name.
     *
     * @param string $stateOrProvinceName The state or province name.
     * @return Principal Returns this instance for fluent interface.
     * @since 0.3
     */
    public function setStateOrProvinceName(string $stateOrProvinceName) : Principal
    {
        $this->stateOrProvinceName = $stateOrProvinceName;
        return $this;
    }

    /**
     * Gets the locality name.
     *
     * @return string Returns the locality name.
     * @since 0.3
     */
    public function getLocalityName() : string
    {
        return $this->localityName;
    }

    /**
     * Sets the locality name.
     *
     * @param string $localityName the locality name.
     * @return Principal Returns this instance for fluent interface.
     * @since 0.3
     */
    public function setLocalityName(string $localityName) : Principal
    {
        $this->localityName = $localityName;
        return $this;
    }

    /**
     * Gets the organization name.
     *
     * @return string the organization name.
     * @since 0.3
     */
    public function getOrganizationName() : string
    {
        return $this->organizationName;
    }

    /**
     * Sets the organization name.
     *
     * @param string $organizationName The organization name.
     * @return Principal Returns this instance for fluent interface.
     * @since 0.3
     */
    public function setOrganizationName(string $organizationName) : Principal
    {
        $this->organizationName = $organizationName;
        return $this;
    }

    /**
     * Gets the organizational unit name.
     *
     * @return string Returns the organizational unit name.
     * @since 0.3
     */
    public function getOrganizationalUnitName() : string
    {
        return $this->organizationalUnitName;
    }

    /**
     * Sets the organizational unit name.
     *
     * @param string $organizationalUnitName The organizational unit name.
     * @return Principal Returns this instance for fluent interface.
     * @since 0.3
     */
    public function setOrganizationalUnitName(string $organizationalUnitName) : Principal
    {
        $this->organizationalUnitName = $organizationalUnitName;
        return $this;
    }

    /**
     * Gets the common name.
     *
     * @return string Returns the common name.
     * @since 0.3
     */
    public function getCommonName() : string
    {
        return $this->commonName;
    }

    /**
     * Sets the common name.
     *
     * @param string $commonName The common name.
     * @return Principal Returns this instance for fluent interface.
     * @since 0.3
     */
    public function setCommonName(string $commonName) : Principal
    {
        $this->commonName = $commonName;
        return $this;
    }

    /**
     * Gests the email address.
     *
     * @return string retunrs the email address.
     * @since 0.3
     */
    public function getEmailAddress() : string
    {
        return $this->emailAddress;
    }

    /**
     * Sets the email address.
     *
     * @param string $emailAddress The email address.
     * @return Principal Returns this instance for fluent interface.
     * @since 0.3
     */
    public function setEmailAddress(string $emailAddress): Principal
    {
        $this->emailAddress = $emailAddress;
        return $this;
    }

    /**
     * Gets the Principal information in an array.
     *
     * @return array Returns the Principal information in an array.
     * @since 0.3
     */
    public function toArray() : array
    {
        return [
            self::PROPERTY_KEY_COUNTRY => $this->getCountryName(),
            self::PROPERTY_KEY_STATE => $this->getStateOrProvinceName(),
            self::PROPERTY_KEY_LOCALITY => $this->getLocalityName(),
            self::PROPERTY_KEY_ORGANIZATION => $this->getOrganizationName(),
            self::PROPERTY_KEY_ORGANIZATIONAL_UNIT => $this->getOrganizationalUnitName(),
            self::PROPERTY_KEY_COMMON_NAME => $this->getCommonName(),
            self::PROPERTY_KEY_EMAIL => $this->getEmailAddress()
        ];
    }

    /**
     * Gets a string representation of the Principal.
     *
     * @return string Returns a string representation of the Principal.
     * @since 0.3
     */
    public function __toString()
    {
        return sprintf('/%s=%s/%s=%s/%s=%s/%s=%s/%s=%s/%s=%s/%s=%s', self::PROPERTY_KEY_COUNTRY,
            $this->getCountryName(), self::PROPERTY_KEY_STATE, $this->getStateOrProvinceName(),
            self::PROPERTY_KEY_LOCALITY, $this->getLocalityName(), self::PROPERTY_KEY_ORGANIZATION,
            $this->getOrganizationName(), self::PROPERTY_KEY_ORGANIZATIONAL_UNIT, $this->getOrganizationalUnitName(),
            self::PROPERTY_KEY_COMMON_NAME, $this->getCommonName(), self::PROPERTY_KEY_EMAIL, $this->getEmailAddress());
    }
}