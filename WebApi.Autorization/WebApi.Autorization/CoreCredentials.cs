using System.Security.Claims;

namespace WebApi.Authorization;

public abstract class CoreCredentials
{
    public List<Claim> Claims { get; } = new List<Claim>();
}
