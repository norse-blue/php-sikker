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

namespace NorseBlue\Sikker\Tests\Certificates;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\Certificates\Principal;

class PrincipalTest extends Unit
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
     * Tests Principal class and functions.
     */
    public function testPrincipal()
    {
        $this->specify('Tests Principal class and functions.', function () {
            $country = 'Westeros';
            $state = 'The North';
            $locality = 'Winterfell';
            $organization = 'Starks';
            $organizationalUnit = 'The Night\'s Watch';
            $commonName = 'www.nightswatch.com';
            $email = 'whitewolf_998@nightswatch.com';

            $principal = new Principal($country, $state, $locality, $organization, $organizationalUnit, $commonName,
                $email);
            $this->assertEquals($country, $principal->getCountryName());
            $this->assertEquals($state, $principal->getStateOrProvinceName());
            $this->assertEquals($locality, $principal->getLocalityName());
            $this->assertEquals($organization, $principal->getOrganizationName());
            $this->assertEquals($organizationalUnit, $principal->getOrganizationalUnitName());
            $this->assertEquals($commonName, $principal->getCommonName());
            $this->assertEquals($email, $principal->getEmailAddress());

            $array = [
                Principal::PROPERTY_KEY_COUNTRY => $country,
                Principal::PROPERTY_KEY_STATE => $state,
                Principal::PROPERTY_KEY_LOCALITY => $locality,
                Principal::PROPERTY_KEY_ORGANIZATION => $organization,
                Principal::PROPERTY_KEY_ORGANIZATIONAL_UNIT => $organizationalUnit,
                Principal::PROPERTY_KEY_COMMON_NAME => $commonName,
                Principal::PROPERTY_KEY_EMAIL => $email
            ];
            $this->assertEquals($array, $principal->toArray());

            $principal2 = Principal::fromArray($array);
            $this->assertEquals($country, $principal2->getCountryName());
            $this->assertEquals($state, $principal2->getStateOrProvinceName());
            $this->assertEquals($locality, $principal2->getLocalityName());
            $this->assertEquals($organization, $principal2->getOrganizationName());
            $this->assertEquals($organizationalUnit, $principal2->getOrganizationalUnitName());
            $this->assertEquals($commonName, $principal2->getCommonName());
            $this->assertEquals($email, $principal2->getEmailAddress());

            $str = sprintf('/%s=%s/%s=%s/%s=%s/%s=%s/%s=%s/%s=%s/%s=%s', Principal::PROPERTY_KEY_COUNTRY, $country,
                Principal::PROPERTY_KEY_STATE, $state, Principal::PROPERTY_KEY_LOCALITY, $locality,
                Principal::PROPERTY_KEY_ORGANIZATION, $organization, Principal::PROPERTY_KEY_ORGANIZATIONAL_UNIT,
                $organizationalUnit, Principal::PROPERTY_KEY_COMMON_NAME, $commonName, Principal::PROPERTY_KEY_EMAIL,
                $email);
            $this->assertEquals($str, $principal->__toString());
        });
    }
}
