# outils-m365

Scripts PowerShell que j'utilise pour administrer des tenants Microsoft 365 de TPE.

## Test-MailDns.ps1

Vérifie la configuration mail d'un domaine à partir du DNS public : MX, SPF, DKIM et DMARC. Ne modifie rien, ne demande aucun accès.

```powershell
.\Test-MailDns.ps1 -Domain "example.org"
```

Ce qu'il signale :

- absence de SPF, plusieurs SPF, SPF trop permissif (`+all`, `?all`) ou au-delà de 10 recherches DNS (include suivis, alerte dès 8)
- DKIM introuvable sur les sélecteurs courants (Microsoft 365, Google, autres), modifiable avec `-DkimSelectors`
- DKIM Microsoft 365 incomplet : selector1 et selector2 doivent être publiés tous les deux
- DMARC absent, en `p=none` ou sans adresse de rapport
- MX absent ou MX nul

Fonctionne sous Windows PowerShell 5.1 et PowerShell 7 (Windows, `Resolve-DnsName`).

## Licence

MIT
