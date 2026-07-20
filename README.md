# PC Audit (C# port)

A direct C# port of your PowerShell audit script. Same sections, same
fallback logic, same "Unknown" defaults, same `Format-List`-style output
(label padded to the widest label, then ` : `, then value).

a C# port of the previous PowerShell script (archived in powershell folder)
does the exact same stuff the same exact way.

## Requirements

- Windows 10/11 (uses WMI/registry/service APIs that only exist on Windows).
- [.NET 8 SDK](https://dotnet.microsoft.com/download).

## Build & run

```powershell
cd PCAudit
dotnet build -c Release
```

Then run the built exe directly (this is what actually triggers the
UAC prompt):

```powershell
.\bin\Release\net8.0-windows\PCAudit.exe
```

or just double-click `PCAudit.exe` in File Explorer.
