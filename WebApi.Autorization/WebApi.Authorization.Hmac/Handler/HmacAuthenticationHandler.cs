using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using WebApi.Authorization.Hmac.ArtefactContainer;
using WebApi.Authorization.Hmac.Providers.Interfaces;

namespace WebApi.Authorization.Hmac.Handler;

public class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationSchemeOptions>
{
    private readonly IHmacAuthCredentialProvider _authCredentialProvider;
    private readonly HmacArtefactContainerParser _artefactContainerParser;

    public HmacAuthenticationHandler(
        IHmacAuthCredentialProvider authCredentialProvider,
        IOptionsMonitor<HmacAuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
        _authCredentialProvider = authCredentialProvider;
        _artefactContainerParser = new HmacArtefactContainerParser();
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            if (!_artefactContainerParser.TryParse(Request.Headers, out var artefactContainer))
            {
                return AuthenticateResult.Fail("Invalid Authorization Header or Scheme");
            }

            var now = ToUnixTimeSecond(Clock.UtcNow);

            if (!IsTimestampFresh(now, artefactContainer.Timestamp, Options.ClockSkewSeconds))
            {
                Logger.LogError(
                    $"{artefactContainer.Scheme}: Invalid timestamp (exp: {now - Options.ClockSkewSeconds} - {now + Options.ClockSkewSeconds}, rcv: {artefactContainer.Timestamp})");

                return AuthenticateResult.Fail("Invalid timestamp");
            }

            var credentials = await _authCredentialProvider.GetCredentialAsync(artefactContainer);

            if (credentials == null)
            {
                return AuthenticateResult.Fail("Invalid authentication header");
            }

            var hmacNormalizedRequest = new HmacNormalizedRequest(Request, artefactContainer, artefactContainer.Scheme);
            Logger.LogInformation($"{artefactContainer.Scheme}: Normalized-Request: {hmacNormalizedRequest}");

            var mac = ComputeHashCode(credentials.Hmac1, hmacNormalizedRequest.ToBytes());
            var authRes = VerifyMac(mac, artefactContainer, artefactContainer.AuthenticationHeaderValue, hmacNormalizedRequest);
            if (authRes != null)
            {
                // Check if the second Hmac is available and matches
                if (credentials.Hmac2 == null)
                {
                    return authRes;
                }

                Logger.LogInformation("First Hmac signature failed; trying second");
                var mac2 = ComputeHashCode(credentials.Hmac2, hmacNormalizedRequest.ToBytes());
                var authRes2 = VerifyMac(mac2, artefactContainer, artefactContainer.AuthenticationHeaderValue, hmacNormalizedRequest);
                if (authRes2 != null)
                {
                    return authRes2;
                }
            }

            var identity = new ClaimsIdentity(credentials.Claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
        catch
        {
            return AuthenticateResult.Fail("Invalid Authorization Header");
        }
    }

    private byte[] ComputeHashCode(System.Security.Cryptography.HMAC hmac, byte[] input)
    {
#if NET6_0_OR_GREATER
        switch (hmac)
        {
            case System.Security.Cryptography.HMACSHA256 _:
                return System.Security.Cryptography.HMACSHA256.HashData(hmac.Key, input);
            case System.Security.Cryptography.HMACSHA1 _:
                return System.Security.Cryptography.HMACSHA1.HashData(hmac.Key, input);
            case System.Security.Cryptography.HMACMD5 _:
                return System.Security.Cryptography.HMACMD5.HashData(hmac.Key, input);
            case System.Security.Cryptography.HMACSHA384 _:
                return System.Security.Cryptography.HMACSHA384.HashData(hmac.Key, input);
            case System.Security.Cryptography.HMACSHA512 _:
                return System.Security.Cryptography.HMACSHA512.HashData(hmac.Key, input);
            default:
                throw new NotSupportedException($"The '{hmac.GetType()}' type is not supported.");
        }
#else
        return hmac.ComputeHash(input);
#endif
    }

    private AuthenticateResult VerifyMac(
        byte[] mac,
        HmacArtefactContainer artifacts,
        AuthenticationHeaderValue authHeader,
        HmacNormalizedRequest normalizedRequest)
    {
        if (mac.Length != artifacts.Mac.Length)
        {
            Logger.LogError(
                $"{authHeader.Scheme}: Hash has different size (exp: {Convert.ToBase64String(mac)}, rcv: {Convert.ToBase64String(artifacts.Mac)})! Normalized request: {normalizedRequest}, AuthParameter: {authHeader.Parameter}");
            return AuthenticateResult.Fail("Invalid Authorization (different mac size)");
        }

        if (mac.Where((t, i) => t != artifacts.Mac[i]).Any())
        {
            Logger.LogError(
                $"{authHeader.Scheme}: Hash is different (exp: {Convert.ToBase64String(mac)}, rcv: {Convert.ToBase64String(artifacts.Mac)})! Normalized request: {normalizedRequest}, AuthParameter: {authHeader.Parameter}");
            return AuthenticateResult.Fail("Invalid Authorization (different mac)");
        }

        return null; // ok
    }

    private static ulong ToUnixTimeSecond(DateTimeOffset dateTime)
    {
        var dateTime1 = new DateTimeOffset(new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc));
        return Convert.ToUInt64((dateTime - dateTime1).TotalSeconds);
    }

    private static bool IsTimestampFresh(ulong nowInSeconds, ulong timestampInSeconds, uint allowedDiff)
    {
        var diff = Math.Abs((double)timestampInSeconds - nowInSeconds);
        return !(diff > allowedDiff); // diff too large
    }
}
