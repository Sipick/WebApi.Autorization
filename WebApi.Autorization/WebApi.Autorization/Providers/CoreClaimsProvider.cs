using System.Security.Claims;

using WebApi.Authorization.Artefact;

namespace WebApi.Authorization.Providers;

public interface CoreClaimsProvider<T> where T : ArtefactContainer
{
    Task<IEnumerable<Claim>> GetClaimsAsync(T artefactContainer);
}
