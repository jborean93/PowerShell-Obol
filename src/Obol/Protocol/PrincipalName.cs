using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Obol.Protocol;

/// <summary>Parses and formats principal names like MIT krb5_parse_name and krb5_unparse_name.</summary>
internal static class PrincipalName
{
    /// <summary>Parses a name like <c>user</c>, <c>HTTP/web.example.test</c> or <c>user@EXAMPLE.TEST</c>.</summary>
    /// <remarks>
    /// The components are separated by '/' and an optional realm follows '@'. A '\' escapes the next character so a
    /// component can contain '/', '@' or '\', and <c>\n</c>, <c>\t</c>, <c>\b</c> and <c>\0</c> are a newline, tab,
    /// backspace and null character. Like MIT the realm cannot contain an unescaped '/' or '@'.
    /// </remarks>
    public static bool TryParse(
        string name,
        [NotNullWhen(true)] out string[]? components,
        out string? realm,
        [NotNullWhen(false)] out string? error)
    {
        components = null;
        realm = null;

        List<string> parts = [];
        StringBuilder current = new();
        bool inRealm = false;
        for (int i = 0; i < name.Length; i++)
        {
            char c = name[i];
            if (c == '\\')
            {
                if (++i == name.Length)
                {
                    error = "the name ends with an incomplete '\\' escape";
                    return false;
                }

                current.Append(name[i] switch
                {
                    'n' => '\n',
                    't' => '\t',
                    'b' => '\b',
                    '0' => '\0',
                    char other => other,
                });
            }
            else if (c == '@')
            {
                if (inRealm)
                {
                    error = "only one unescaped '@' is allowed";
                    return false;
                }
                parts.Add(current.ToString());
                current.Clear();
                inRealm = true;
            }
            else if (c == '/')
            {
                if (inRealm)
                {
                    error = "the realm cannot contain an unescaped '/'";
                    return false;
                }
                parts.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        if (inRealm)
        {
            realm = current.ToString();
            if (realm.Length == 0)
            {
                error = "the realm after '@' is empty";
                return false;
            }
        }
        else
        {
            parts.Add(current.ToString());
        }

        foreach (string part in parts)
        {
            if (part.Length == 0)
            {
                error = "a name component is empty";
                return false;
            }
        }

        components = [.. parts];
        error = null;
        return true;
    }

    /// <summary>Formats the name components joined by '/' with the characters that need it escaped.</summary>
    public static string Unparse(IEnumerable<string> components)
    {
        StringBuilder sb = new();
        foreach (string component in components)
        {
            if (sb.Length > 0)
            {
                sb.Append('/');
            }

            foreach (char c in component)
            {
                sb.Append(c switch
                {
                    '/' => @"\/",
                    '@' => @"\@",
                    '\\' => @"\\",
                    '\n' => @"\n",
                    '\t' => @"\t",
                    '\b' => @"\b",
                    '\0' => @"\0",
                    _ => c.ToString(),
                });
            }
        }

        return sb.ToString();
    }
}
