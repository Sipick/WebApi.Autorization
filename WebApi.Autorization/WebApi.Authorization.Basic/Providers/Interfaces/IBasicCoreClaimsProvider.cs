using WebApi.Authorization.Basic.ArtefactContainer;
using WebApi.Authorization.Providers;

namespace WebApi.Authorization.Basic.Providers.Interfaces
{
    public interface IBasicCoreClaimsProvider : CoreClaimsProvider<BasicArtefactContainer> { }
}