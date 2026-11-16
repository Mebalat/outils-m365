<#
.SYNOPSIS
    Vérifie la configuration mail d'un domaine : MX, SPF, DKIM et DMARC.

.DESCRIPTION
    Lit les enregistrements DNS publics du domaine et signale ce qui manque
    ou ce qui est trop permissif. Aucune modification n'est faite.

.EXAMPLE
    .\Test-MailDns.ps1 -Domain "example.org"

.EXAMPLE
    .\Test-MailDns.ps1 -Domain "example.org" -DkimSelectors "s1","s2" -OutputFile ".\rapport.txt"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    # Sélecteurs DKIM courants : Microsoft 365 (selector1, selector2), Google (google), autres hébergeurs
    [string[]]$DkimSelectors = @("selector1", "selector2", "google", "default", "dkim", "k1", "mail"),

    [string]$OutputFile = ""
)

$lines    = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

function Add-Line([string]$text) { $lines.Add($text) }

function Get-TxtRecords([string]$name) {
    try {
        Resolve-DnsName -Name $name -Type TXT -ErrorAction Stop |
            Where-Object { $_.Type -eq "TXT" } |
            ForEach-Object { $_.Strings -join "" }
    } catch {
        @()
    }
}

# Compte les recherches DNS d'un SPF en suivant les include et redirect (limite de 10, RFC 7208).
# $visited évite de boucler si deux SPF s'incluent l'un l'autre.
function Get-SpfLookupCount([string]$name, [System.Collections.Generic.HashSet[string]]$visited) {
    if (-not $visited.Add($name.ToLower())) { return 0 }
    $record = Get-TxtRecords $name | Where-Object { $_ -match "^v=spf1" } | Select-Object -First 1
    if (-not $record) { return 0 }

    $count = 0
    foreach ($term in ($record -split "\s+")) {
        if ($term -match "^[+\-~?]?(include:|redirect=)(.+)$") {
            $count += 1 + (Get-SpfLookupCount $Matches[2] $visited)
        } elseif ($term -match "^[+\-~?]?(a|mx|ptr|exists)(:|/|$)") {
            $count++
        }
    }
    return $count
}

Add-Line "Configuration mail de $Domain"
Add-Line "Date : $(Get-Date -Format 'dd/MM/yyyy HH:mm')"
Add-Line ""

# --- MX ---
Add-Line "[MX]"
$mx = @()
$provider = "autre ou inconnu"
try {
    $mx = Resolve-DnsName -Name $Domain -Type MX -ErrorAction Stop |
        Where-Object { $_.Type -eq "MX" } | Sort-Object Preference
} catch { }

if ($mx.Count -eq 0) {
    Add-Line "  Aucun enregistrement MX"
    $warnings.Add("Aucun MX : le domaine ne peut pas recevoir de mail.")
} else {
    foreach ($r in $mx) { Add-Line "  $($r.Preference)  $($r.NameExchange)" }
    if ($mx.Count -eq 1 -and ($mx[0].NameExchange -eq "." -or [string]::IsNullOrEmpty($mx[0].NameExchange))) {
        $warnings.Add("MX nul (RFC 7505) : le domaine déclare ne recevoir aucun mail.")
    }
    $hosts = ($mx.NameExchange -join " ").ToLower()
    if   ($hosts -match "protection\.outlook\.com|mail\.protection") { $provider = "Microsoft 365" }
    elseif ($hosts -match "google\.com|googlemail\.com")               { $provider = "Google Workspace" }
    elseif ($hosts -match "ovh\.net")                                  { $provider = "OVH" }
    elseif ($hosts -match "infomaniak")                                { $provider = "Infomaniak" }
    elseif ($hosts -match "gandi\.net")                                { $provider = "Gandi" }
    Add-Line "  Hébergeur probable : $provider"
}
Add-Line ""

# --- SPF ---
Add-Line "[SPF]"
$spf = @(Get-TxtRecords $Domain | Where-Object { $_ -match "^v=spf1" })

if ($spf.Count -eq 0) {
    Add-Line "  Aucun enregistrement SPF"
    $warnings.Add("Pas de SPF : n'importe quel serveur peut envoyer au nom du domaine.")
} elseif ($spf.Count -gt 1) {
    $spf | ForEach-Object { Add-Line "  $_" }
    $warnings.Add("Plusieurs enregistrements SPF : c'est une erreur, ils doivent être fusionnés en un seul.")
} else {
    $value = $spf[0]
    Add-Line "  $value"

    if     ($value -match "-all$")  { Add-Line "  Politique : stricte (-all)" }
    elseif ($value -match "~all$")  { Add-Line "  Politique : souple (~all), courant et acceptable" }
    elseif ($value -match "\?all$") { $warnings.Add("SPF en ?all : neutre, il ne protège rien.") }
    elseif ($value -match "\+all$") { $warnings.Add("SPF en +all : autorise tout le monde, à corriger en priorité.") }
    else                            { $warnings.Add("SPF sans mécanisme all final.") }

    $visited = New-Object System.Collections.Generic.HashSet[string]
    $lookups = Get-SpfLookupCount $Domain $visited
    Add-Line "  Recherches DNS : $lookups sur 10 autorisées (include suivis)"
    if ($lookups -gt 10) { $warnings.Add("SPF à $lookups recherches DNS, au-delà de 10 : il est invalide pour les serveurs destinataires.") }
    elseif ($lookups -ge 8) { $warnings.Add("SPF à $lookups recherches DNS sur 10 : peu de marge pour ajouter un service d'envoi.") }
}
Add-Line ""

# --- DKIM ---
Add-Line "[DKIM]"
$dkimFound = $false
$dkimActive = @()
foreach ($sel in $DkimSelectors) {
    $rec = @(Get-TxtRecords "$sel._domainkey.$Domain" | Where-Object { $_ -match "v=DKIM1|p=" })
    if ($rec.Count -gt 0) {
        $dkimFound = $true
        if ($rec[0] -match "p=;|p=$") {
            Add-Line "  $sel : présent mais clé vide (révoquée)"
        } else {
            Add-Line "  $sel : présent"
            $dkimActive += $sel
        }
    }
}

# Microsoft 365 alterne entre deux clés : selector1 et selector2 doivent être publiés tous les deux,
# sinon la signature échoue le jour où Microsoft passe sur la clé manquante.
$usesM365 = ($provider -eq "Microsoft 365") -or (($spf -join " ") -match "spf\.protection\.outlook\.com")
if ($usesM365 -and ($DkimSelectors -contains "selector1") -and ($DkimSelectors -contains "selector2")) {
    $has1 = $dkimActive -contains "selector1"
    $has2 = $dkimActive -contains "selector2"
    if ($has1 -xor $has2) {
        $missing = if ($has1) { "selector2" } else { "selector1" }
        $warnings.Add("DKIM Microsoft 365 incomplet : $missing absent. Créer le CNAME $missing._domainkey indiqué dans Defender, sinon la signature échouera à la rotation de clé.")
    } elseif (-not $has1 -and -not $has2) {
        $warnings.Add("DKIM Microsoft 365 non publié : selector1 et selector2 absents. Créer les deux CNAME puis activer DKIM dans Defender.")
    }
}
if (-not $dkimFound) {
    Add-Line "  Aucun sélecteur trouvé parmi : $($DkimSelectors -join ', ')"
    $warnings.Add("DKIM non trouvé. Vérifier le sélecteur utilisé par l'hébergeur (paramètre -DkimSelectors).")
}
Add-Line ""

# --- DMARC ---
Add-Line "[DMARC]"
$dmarc = @(Get-TxtRecords "_dmarc.$Domain" | Where-Object { $_ -match "^v=DMARC1" })

if ($dmarc.Count -eq 0) {
    Add-Line "  Aucun enregistrement DMARC"
    $warnings.Add("Pas de DMARC : aucune consigne aux destinataires en cas d'usurpation du domaine.")
} else {
    $value = $dmarc[0]
    Add-Line "  $value"
    $policy = if ($value -match "(?:^|;)\s*p=(\w+)") { $Matches[1].ToLower() } else { "" }
    switch ($policy) {
        "reject"     { Add-Line "  Politique : reject, les mails usurpés sont refusés" }
        "quarantine" { Add-Line "  Politique : quarantine, les mails usurpés vont en indésirables" }
        "none"       { $warnings.Add("DMARC en p=none : surveillance seulement, aucune protection. Passer à quarantine quand SPF et DKIM sont en place.") }
        default      { $warnings.Add("DMARC sans politique p= lisible.") }
    }
    if ($value -notmatch "rua=") { $warnings.Add("DMARC sans adresse rua= : aucun rapport n'est reçu.") }
}
Add-Line ""

# --- Bilan ---
Add-Line "[BILAN]"
if ($warnings.Count -eq 0) {
    Add-Line "  Rien à signaler."
} else {
    foreach ($w in $warnings) { Add-Line "  - $w" }
}

$lines | ForEach-Object { Write-Host $_ }

if ($OutputFile) {
    $lines | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host ""
    Write-Host "Rapport enregistré : $OutputFile"
}
