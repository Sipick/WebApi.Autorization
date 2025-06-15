namespace WebApi.Authorization.Hmac.ArtefactContainer;

public class HmacArtefactContainer : Artefact.ArtefactContainer
{
    public string Id { get; set; }

    public ulong Timestamp { get; set; }

    public string Nonce { get; set; }

    public string ApplicationSpecificData { get; set; }

    public byte[] Mac { get; set; }

    public byte[] PayloadHash { get; set; }

    public bool IsValid
    {
        get
        {
            return !string.IsNullOrEmpty(Id) &&
                   !string.IsNullOrEmpty(Nonce) &&
                   Mac != null &&
                   Mac.Length > 0 &&
                   Timestamp > 0UL;
        }
    }
}
