// WiX 3 fixture build hook. Let WiX generate a fresh PackageCode, then bind
// that identity into the payload before WiX creates the cabinet. The normal
// file metadata, ICE validation and warning checks remain enabled.
using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Tools.WindowsInstallerXml;

[assembly: AssemblyDefaultWixExtension(typeof(RuntimeMsiManifestExtension))]

public sealed class RuntimeMsiManifestExtension : WixExtension
{
    private readonly RuntimeMsiManifestBinder binder = new RuntimeMsiManifestBinder();
    public override BinderExtension BinderExtension { get { return binder; } }
}

public sealed class RuntimeMsiManifestBinder : BinderExtensionEx
{
    private static Row FindRow(Table table, string key)
    {
        Row found = null;
        if (table == null) { throw new InvalidOperationException("Missing MSI manifest binding table"); }
        foreach (Row row in table.Rows)
        {
            if (Convert.ToString(row[0], CultureInfo.InvariantCulture) == key)
            {
                if (found != null) { throw new InvalidOperationException("Duplicate MSI manifest binding row"); }
                found = row;
            }
        }
        if (found == null) { throw new InvalidOperationException("Missing MSI manifest binding row: " + key); }
        return found;
    }

    public override void DatabaseAfterResolvedFields(Output output)
    {
        string code = (string)FindRow(output.Tables["_SummaryInformation"], "9")[1];
        Guid parsed;
        if (!Guid.TryParseExact(code, "B", out parsed) || parsed == Guid.Empty ||
            parsed.ToString("B").ToUpperInvariant() != code)
        {
            throw new InvalidOperationException("WiX did not generate a canonical package identity");
        }
        FileRow file = FindRow(output.Tables["File"], "ManifestFile") as FileRow;
        if (file == null) { throw new InvalidOperationException("Manifest is not a bound file"); }
        string text = File.ReadAllText(file.Source, Encoding.UTF8);
        Regex placeholder = new Regex("(\"msi_package_code\"\\s*:\\s*\")\\{00000000-0000-0000-0000-000000000000\\}(\")");
        if (placeholder.Matches(text).Count != 1)
        {
            throw new InvalidOperationException("Manifest requires one unresolved package identity");
        }
        text = placeholder.Replace(text, delegate(Match match) { return match.Groups[1].Value + code + match.Groups[2].Value; });
        byte[] bytes = new UTF8Encoding(false, true).GetBytes(text);
        if (bytes.Length == 0 || bytes.Length > 4096) { throw new InvalidOperationException("Manifest exceeds its runtime bound"); }
        Row action = FindRow(output.Tables["CustomAction"], "ValidateInstalledRuntime");
        if ((string)action[2] != "RuntimeFile" || (string)action[3] != "--check-installation")
        {
            throw new InvalidOperationException("Unexpected installed-manifest validation action");
        }
        string digest;
        using (SHA256 hash = SHA256.Create())
        {
            digest = BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        }
        File.WriteAllBytes(file.Source, bytes);
        action[3] = "--check-installation " + digest;
        // The extended binder's supported updated-file table makes WiX
        // recalculate size/hash before cabinet creation and ICE validation.
        output.Tables["WixBindUpdatedFiles"].CreateRow(null)[0] = "ManifestFile";
    }
}
