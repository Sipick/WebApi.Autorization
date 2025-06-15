using System.Security.Claims;

using Microsoft.Extensions.Logging;

using WebApi.Authorization.Hmac.ArtefactContainer;
using WebApi.Authorization.Hmac.Providers.Interfaces;

namespace WebApi.Authorization.Hmac.Providers;

public class HmacCoreClaimsProvider : IHmacCoreClaimsProvider
{
    private readonly IHmacDataSourceProvider _hmacDataSourceProvider;
    private readonly ILogger<HmacCoreClaimsProvider> _logger;

    public HmacCoreClaimsProvider(IHmacDataSourceProvider hmacDataSourceProvider, ILogger<HmacCoreClaimsProvider> logger)
    {
        _hmacDataSourceProvider = hmacDataSourceProvider;
        _logger = logger;
    }

    public async Task<IEnumerable<Claim>> GetClaimsAsync(HmacArtefactContainer artefactContainer)
    {
        return await _hmacDataSourceProvider.GetClaimsAsync(artefactContainer);
    }
}
