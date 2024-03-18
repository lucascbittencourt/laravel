<?php

namespace AbuseIPDB;

use AbuseIPDB\Exceptions\InvalidParameterException;
use AbuseIPDB\Exceptions\MissingAPIKeyException;
use AbuseIPDB\Exceptions\PaymentRequiredException;
use AbuseIPDB\Exceptions\TooManyRequestsException;
use AbuseIPDB\Exceptions\UnconventionalErrorException;
use AbuseIPDB\Exceptions\UnprocessableContentException;
use AbuseIPDB\ResponseObjects\BlacklistPlaintextResponse;
use AbuseIPDB\ResponseObjects\BlacklistResponse;
use AbuseIPDB\ResponseObjects\BulkReportResponse;
use AbuseIPDB\ResponseObjects\CheckBlockResponse;
use AbuseIPDB\ResponseObjects\CheckResponse;
use AbuseIPDB\ResponseObjects\ClearAddressResponse;
use AbuseIPDB\ResponseObjects\ReportResponse;
use AbuseIPDB\ResponseObjects\ReportsPaginatedResponse;
use BadMethodCallException;
use DateTime;
use DateTimeInterface;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Http\Response as HttpResponse;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Traits\ForwardsCalls;

class AbuseIPDBLaravel
{
    use ForwardsCalls;

    /**
     * Methods available and HTTP request verbs
     *
     * @var array
     */
    private array $methods = [
        'get',
        'post',
        'delete',
        'check',
        'checkBlock',
        'clearAddress',
        'blacklist',
        'blacklistPlainText',
        'bulkReport',
        'report',
        'reports',
    ];

    /**
     * Attacks categories available with their respective identifier
     *
     * @var array<string>
     */
    private array $categories = [
        'DNS_Compromise' => 1,
        'DNS_Poisoning' => 2,
        'Fraud_Orders' => 3,
        'DDoS_Attack' => 4,
        'FTP_Brute_Force' => 5,
        'Ping_of_Death' => 6,
        'Phishing' => 7,
        'Fraud_VoIP' => 8,
        'Open_Proxy' => 9,
        'Web_Spam' => 10,
        'Email_Spam' => 11,
        'Blog_Spam' => 12,
        'VPN_IP' => 13,
        'Port_Scan' => 14,
        'Hacking' => 15,
        'SQL_Injection' => 16,
        'Spoofing' => 17,
        'Brute_Force' => 18,
        'Bad_Web_Bot' => 19,
        'Exploited_Host' => 20,
        'Web_App_Attack' => 21,
        'SSH' => 22,
        'IoT_Targeted' => 23,
    ];

    /**
     * @throws MissingAPIKeyException
     */
    public function __construct(private PendingRequest $request)
    {
        if (!config('abuseipdb.api_key')) {
            throw new MissingAPIKeyException('ABUSEIPDB_API_KEY must be set in .env with an AbuseIPBD API key.');
        }

        $this->request = Http::baseUrl(config('abuseipdb.base_url'))
            ->withHeaders([
                'X-Request-Source' => 'Laravel_' . app()->version() . ';Laravel_' . config('abuseipdb.version') . ';',
                'Key' => config('abuseipdb.api_key'),
            ]);
    }

    /**
     * @param string $method
     * @param array $parameters
     * @return Response
     * @throws PaymentRequiredException
     * @throws TooManyRequestsException
     * @throws UnconventionalErrorException
     * @throws UnprocessableContentException
     */
    public function __call(string $method, array $parameters): Response
    {
        if (!in_array($method, $this->methods)) {
            throw new BadMethodCallException(sprintf(
                'Call to undefined method %s::%s()', static::class, $method
            ));
        }

        $response = $this->forwardCallTo($this->request, $method, $parameters);

        $status = $response->status();

        if ($status !== HttpResponse::HTTP_OK) {
            $message = 'AbuseIPDB: ' . $response->object()->errors[0]->detail;

            match ($status) {
                HttpResponse::HTTP_TOO_MANY_REQUESTS => throw new TooManyRequestsException($message),
                HttpResponse::HTTP_PAYMENT_REQUIRED => throw new PaymentRequiredException($message),
                HttpResponse::HTTP_UNPROCESSABLE_ENTITY => throw new UnprocessableContentException($message),
                default => throw new UnconventionalErrorException($message),
            };
        }

        return $response;
    }

    /**
     * Checks an IP address against the AbuseIPDB database
     *
     * @param string $ipAddress The IP address to check
     * @param int $maxAgeInDays The maximum age in days of reports to return
     * @param bool $verbose Whether to include verbose information (reports)
     * @throws InvalidParameterException
     */
    public function check(string $ipAddress, int $maxAgeInDays = 30, bool $verbose = false): CheckResponse
    {
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            throw InvalidParameterException::invalidIpAddress($ipAddress);
        }

        if ($maxAgeInDays < 1 || $maxAgeInDays > 365) {
            throw InvalidParameterException::maxAgeInDaysOutOfRange($maxAgeInDays);
        }

        $checkResponse = $this->request->get('check', [
            'ipAddress' => $ipAddress,
            'maxAgeInDays' => $maxAgeInDays,
            'verbose' => $verbose,
        ]);

        return new CheckResponse($checkResponse);
    }

    /**
     * Checks an entire subnet against the AbuseIPDB database
     *
     * @param string $network The network to check in CIDR notation (e.g. 127.0.0.1/28)
     * @param int $maxAgeInDays The maximum age in days of reports to return
     * @throws InvalidParameterException
     */
    public function checkBlock(string $network, int $maxAgeInDays = 30): CheckBlockResponse
    {
        if ($maxAgeInDays < 1 || $maxAgeInDays > 365) {
            throw InvalidParameterException::maxAgeInDaysOutOfRange($maxAgeInDays);
        }

        $checkBlockResponse = $this->request->get('check-block', [
            'network' => $network,
            'maxAgeInDays' => $maxAgeInDays,
        ]);

        return new CheckBlockResponse($checkBlockResponse);
    }

    /**
     * Remove your reports for an IP address from the AbuseIPDB database.
     *
     * @param string $ipAddress The IP address to clear reports for
     * @throws InvalidParameterException
     */
    public function clearAddress(string $ipAddress): ClearAddressResponse
    {
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            throw InvalidParameterException::invalidIpAddress($ipAddress);
        }

        $clearAddressResponse = $this->request->delete('clear-address', [
            'ipAddress' => $ipAddress,
        ]);

        return new ClearAddressResponse($clearAddressResponse);
    }

    /**
     * Gets the AbuseIPDB blacklist
     *
     * @param int $confidenceMinimum The minimum confidence score to include an IP in the blacklist.
     * @param int $limit The maximum amount blacklisted IPs to return.
     * @param array $onlyCountries Only include IPs from these countries (use 2-letter country codes).
     * @param array $exceptCountries Exclude IPs from these countries (use 2-letter country codes).
     * @param int|null $ipVersion The IP version to return (4 or 6), defaults to both.
     * @throws InvalidParameterException
     */
    public function blacklist(int $confidenceMinimum = 100, int $limit = 10000, array $onlyCountries = [], array $exceptCountries = [], int $ipVersion = null): ResponseObjects\BlacklistResponse|ResponseObjects\BlacklistPlaintextResponse
    {
        if ($confidenceMinimum < 25 || $confidenceMinimum > 100) {
            throw InvalidParameterException::minimumConfidenceOutOfRange($confidenceMinimum);
        }

        $invalidOnlyCountries = array_filter($onlyCountries, fn($countryCode) => !strlen($countryCode) == 2);
        $invalidExceptCountries = array_filter($exceptCountries, fn($countryCode) => !strlen($countryCode) == 2);

        if ($invalidOnlyCountries) {
            throw InvalidParameterException::invalidOnlyCountriesCode($invalidOnlyCountries);
        }

        if ($invalidExceptCountries) {
            throw InvalidParameterException::invalidExceptCountriesCode($invalidExceptCountries);
        }

        if (!in_array($ipVersion, [4, 6])) {
            throw InvalidParameterException::invalidIpVersion($ipVersion);
        }

        $blacklistResponse = $this->request->get('blacklist', [
            'confidenceMinimum' => $confidenceMinimum,
            'limit' => $limit,
            'onlyCountries' => $onlyCountries,
            'exceptCountries' => $exceptCountries,
            'ipVersion' => $ipVersion,
        ]);

        return new BlacklistResponse($blacklistResponse);
    }

    /**
     * Gets the AbuseIPDB blacklist in a plaintext (a plain array of IPs)
     *
     * @param int $confidenceMinimum The minimum confidence score to include an IP in the blacklist.
     * @param int $limit The maximum amount blacklisted IPs to return
     * @param array $onlyCountries Only include IPs from these countries (use 2-letter country codes)
     * @param array $exceptCountries Exclude IPs from these countries (use 2-letter country codes)
     * @param int|null $ipVersion The IP version to return (4 or 6), defaults to both.
     * @throws InvalidParameterException
     */
    public function blacklistPlainText(int $confidenceMinimum = 100, int $limit = 10000, array $onlyCountries = [], array $exceptCountries = [], int $ipVersion = null): BlacklistPlaintextResponse
    {
        if ($confidenceMinimum < 25 || $confidenceMinimum > 100) {
            throw InvalidParameterException::minimumConfidenceOutOfRange($confidenceMinimum);
        }

        $invalidOnlyCountries = array_filter($onlyCountries, fn($countryCode) => !strlen($countryCode) == 2);
        $invalidExceptCountries = array_filter($exceptCountries, fn($countryCode) => !strlen($countryCode) == 2);

        if ($invalidOnlyCountries) {
            throw InvalidParameterException::invalidOnlyCountriesCode($invalidOnlyCountries);
        }

        if ($invalidExceptCountries) {
            throw InvalidParameterException::invalidExceptCountriesCode($invalidExceptCountries);
        }

        if (!in_array($ipVersion, [4, 6])) {
            throw InvalidParameterException::invalidIpVersion($ipVersion);
        }

        $blacklistPlainTextResponse = $this->request
            ->accept('text/plain')
            ->get('blacklist', [
                'confidenceMinimum' => $confidenceMinimum,
                'limit' => $limit,
                'onlyCountries' => $onlyCountries,
                'exceptCountries' => $exceptCountries,
                'ipVersion' => $ipVersion,
            ]);

        return new BlacklistPlaintextResponse($blacklistPlainTextResponse);
    }

    /**
     * Reports multiple IP addresses to AbuseIPDB in bulk from a csv.
     *
     * @param string $csvFileContents The contents of the csv file to upload
     */
    public function bulkReport(string $csvFileContents): BulkReportResponse
    {
        $bulkReportResponse = $this->request
            ->attach('csv', $csvFileContents, 'report.csv')
            ->post('bulk-report');

        return new BulkReportResponse($bulkReportResponse);
    }

    /**
     * Reports an IP address to AbuseIPDB
     *
     * @param string $ipAddress The IP address to report
     * @param array<string>|string $categories The categories to report the IP address for
     * @param string|null $comment A comment to include with the report
     * @param DateTime|null $timestamp A timestamp to include with the report
     * @throws InvalidParameterException
     */
    public function report(string $ipAddress, array|int $categories, string $comment = null, DateTimeInterface $timestamp = null): ReportResponse
    {
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            throw InvalidParameterException::invalidIpAddress($ipAddress);
        }

        if (!is_array($categories)) {
            $categories = [$categories];
        }

        $invalidCategories = array_diff($categories, $this->categories);

        if (!empty($invalidCategories)) {
            throw InvalidParameterException::invalidCategories($invalidCategories);
        }

        $reportResponse = $this->request->post('report', [
            'ip' => $ipAddress,
            'categories' => $categories,
            'comment' => $comment,
            'timestamp' => $timestamp?->format(DateTimeInterface::ATOM),
        ]);

        return new ReportResponse($reportResponse);
    }

    /**
     * Get the reports for a single IP address
     *
     * @param string $ipAddress The IP address to get reports for
     * @param int $maxAgeInDays The maximum age in days of reports to return
     * @param int $page The page number to get
     * @param int $perPage The amount reports to get per page
     * @throws InvalidParameterException
     */
    public function reports(string $ipAddress, int $maxAgeInDays = 30, int $page = 1, int $perPage = 25): ReportsPaginatedResponse
    {
        if ($maxAgeInDays < 1 || $maxAgeInDays > 365) {
            throw InvalidParameterException::maxAgeInDaysOutOfRange($maxAgeInDays);
        }

        if ($page < 1) {
            throw InvalidParameterException::pageOutOfRange($page);
        }

        if ($perPage < 1 || $perPage > 100) {
            throw InvalidParameterException::perPageOutOfRange($perPage);
        }

        $reportsResponse = $this->request->get('reports', [
            'ipAddress' => $ipAddress,
            'maxAgeInDays' => $maxAgeInDays,
            'page' => $page,
            'perPage' => $perPage,
        ]);

        return new ReportsPaginatedResponse($reportsResponse);
    }
}
