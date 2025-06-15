namespace WebApi.Authorization;

public class BasicCredentials : CoreCredentials
{
    public string Username { get; set; }
    public string Password { get; set; }
}
