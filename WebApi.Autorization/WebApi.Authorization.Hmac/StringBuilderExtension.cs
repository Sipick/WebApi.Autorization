using System.Text;

namespace WebApi.Authorization.Hmac;

internal static class StringBuilderExtension
{
    internal static StringBuilder AppendIfNotEmpty(this StringBuilder builder, string key, string value, char trailer)
    {
        if (!string.IsNullOrEmpty(value))
        {
            builder.AppendFormat("{0}=\"{1}\"", key, value).Append(trailer).Append(" ");
        }

        return builder;
    }

    internal static StringBuilder AppendNewLine(this StringBuilder builder, string value)
    {
        builder.Append(value ?? string.Empty).Append("\n");
        return builder;
    }
}
