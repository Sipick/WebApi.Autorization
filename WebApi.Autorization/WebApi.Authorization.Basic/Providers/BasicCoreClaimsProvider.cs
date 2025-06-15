using System.Security.Claims;

using Microsoft.Extensions.Logging;

using WebApi.Authorization.Basic.ArtefactContainer;
using WebApi.Authorization.Basic.Providers.Interfaces;

namespace WebApi.Authorization.Basic.Providers;

public class BasicCoreClaimsProvider : IBasicCoreClaimsProvider
{
    private readonly IBasicDataSourceProvider _basicDataSourceProvider;
    private readonly ILogger<BasicCoreClaimsProvider> _logger;

    public BasicCoreClaimsProvider(IBasicDataSourceProvider basicDataSourceProvider, ILogger<BasicCoreClaimsProvider> logger)
    {
        _basicDataSourceProvider = basicDataSourceProvider;
        _logger = logger;
    }

    public async Task<IEnumerable<Claim>> GetClaimsAsync(BasicArtefactContainer artefactContainer)
    {
        return await _basicDataSourceProvider.GetClaimsAsync(artefactContainer);
    }
}
