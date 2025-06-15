using WebApi.Authorization.Hmac.ArtefactContainer;
using WebApi.Authorization.Providers;

namespace WebApi.Authorization.Hmac.Providers.Interfaces;

public interface IHmacCoreClaimsProvider : CoreClaimsProvider<HmacArtefactContainer> { }
