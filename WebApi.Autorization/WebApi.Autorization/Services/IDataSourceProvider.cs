using System.Security.Claims;

using WebApi.Authorization.Artefact;

namespace WebApi.Authorization.Services;

public interface IDataSourceProvider<in TContainer, TCredentials> where TContainer : ArtefactContainer
    where TCredentials : CoreCredentials
{
    Task<TCredentials> GetCredentialAsync(TContainer container);

    Task<IEnumerable<Claim>> GetClaimsAsync(TContainer container);
}
