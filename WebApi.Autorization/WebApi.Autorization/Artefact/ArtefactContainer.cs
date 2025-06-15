using System.Net.Http.Headers;

namespace WebApi.Authorization.Artefact;

public abstract class ArtefactContainer
{
    public string Scheme {get; set; }

    public AuthenticationHeaderValue AuthenticationHeaderValue { get; set; }
}
