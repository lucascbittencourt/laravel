<?php

namespace AbuseIPDB\Exceptions;

use Exception;

class InvalidParameterException extends Exception
{
    public static function invalidIpAddress(string $ipAddress): static
    {
        return new static(sprintf('AbuseIPDB: "%s" is not a valid IP address.', $ipAddress));
    }

    public static function maxAgeInDaysOutOfRange(int $maxAgeInDays): static
    {
        return new static(sprintf('AbuseIPDB: "maxAgeInDays" must be between 1 and 365 given "%s".', $maxAgeInDays));
    }

    public static function invalidCategories(array $categories): static
    {
        return new static(sprintf('AbuseIPDB: "%s" are not valid categories.', implode(', ', $categories)));
    }

    public static function pageOutOfRange($page): static
    {
        return new static(sprintf('AbuseIPDB: "page" must be at least 1 given "%s".', $page));
    }

    public static function perPageOutOfRange($perPage): static
    {
        return new static(sprintf('AbuseIPDB: "perPage" must be between 1 and 100 given "%s".', $perPage));
    }

    public static function minimumConfidenceOutOfRange(int $minimumConfidence): static
    {
        return new static(sprintf('AbuseIPDB: "minimumConfidence" must be between 25 and 100 given "%s".', $minimumConfidence));
    }

    public function invalidOnlyCountriesCode(array $countries): static
    {
        return new static(sprintf('AbuseIPDB: Country codes must be 2 characters long given "%s".', implode(', ', $countries)));
    }

    public function invalidExceptCountriesCode(array $countries): static
    {
        return new static(sprintf('AbuseIPDB: Country codes must be 2 characters long given "%s".', implode(', ', $countries)));
    }

    public static function invalidIpVersion(int $ipVersion): static
    {
        return new static(sprintf('AbuseIPDB: "ipVersion" must be 4 or 6 given "%s".', $ipVersion));
    }
}
