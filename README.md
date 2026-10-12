# ISO-Guard 🛡️

ISO-Guard, **ISO/IEC 27001:2022** teknik ve organizasyonel kontrollerini (Ek A / Annex A) hedef dosya sistemleri, kaynak kod depoları ve işletim sistemi ortamları üzerinde otomatik olarak denetleyen, modüler ve genişletilebilir bir Go CLI aracıdır.

---

## 📁 Proje Dizin Yapısı

Proje, Go ekosisteminin en iyi pratiklerine ve Clean Architecture ilkelerine uygun olarak modüler şekilde tasarlanmıştır:

```text
iso-guard/
├── cmd/                        # Cobra CLI komutları ve argüman yönetimi
│   ├── root.go                 # Temel komut, global bayraklar ve Viper entegrasyonu
│   ├── scan.go                 # `scan` komutu: hedef denetimini çalıştırır
│   ├── list_rules.go           # `list-rules` komutu: kuralları listeler ve filtreler
│   └── version.go              # `version` komutu: sürüm ve derleme bilgileri
├── config/                     # Yapılandırma yönetimi (YAML & Ortam Değişkenleri)
│   └── config.go               # Viper tabanlı şema ve varsayılan ayarlar
├── engine/                     # Çekirdek kural motoru ve değerlendirme mekanizması
│   ├── engine.go               # Tarayıcı orkestrasyonu, kural yürütme ve skorlama
│   ├── rule.go                 # Kural tanımı, bağlam (ScanContext) ve fonksiyon tipleri
│   ├── registry.go             # Dinamik kural kayıt defteri (Registry)
│   ├── result.go               # Sonuç modelleri, önem seviyeleri ve metrikler
│   └── policy/                 # YAML Tabanlı Kural Motoru (Policy Engine)
│       ├── model.go            # Bildirimsel YAML politika ve assertion veri modeli
│       ├── evaluator.go        # Değerlendirici arayüzü ve assertion doğrulayıcısı
│       └── engine.go           # YAML yükleme, ayrıştırma ve orkestrasyon
├── policies/                   # Harici YAML politika tanımları
│   └── iso27001-sample-rules.yaml # Parola ve Branch Koruma kuralları
├── scanners/                   # Veri toplama ve hedef keşif modülleri
│   ├── scanner.go              # Tarayıcı temel arayüzü (Scanner Interface)
│   ├── file/                   # Dosya sistemi ve izin tarayıcısı
│   │   └── file_scanner.go
│   ├── system/                 # İşletim sistemi ve çevre değişkenleri denetleyicisi
│   │   └── system_scanner.go
│   └── network/                # Ağ portları ve şifrelenmemiş protokol tarayıcısı
│       └── network_scanner.go
├── reporters/                  # Rapor formatlayıcıları
│   ├── reporter.go             # Raporlayıcı arayüzü ve format fabrikası
│   ├── console.go              # Renkli terminal çıktısı ve uyumluluk özeti
│   ├── json.go                 # CI/CD için makinece okunabilir JSON çıktısı
│   └── markdown.go             # Denetim belgeleri için detaylı Markdown raporu
├── rules/                      # ISO 27001:2022 kontrolleri
│   └── rules.go                # Yerleşik Annex A kontrolleri ve değerlendirme kuralları
├── iso-guard.yaml              # Örnek yapılandırma dosyası
├── main.go                     # Uygulama giriş noktası
└── .gitignore                  # Git yoksayma kuralları
```

---

## 🚀 Kurulum ve Derleme

### Gereksinimler
- Go 1.21 veya üzeri

### Derleme
```powershell
# Bağımlılıkları indir ve derle
go build -o iso-guard.exe .
```

---

## 🛠️ Kullanım Rehberi

### 1. Hedef Tarama (`scan`)
Varsayılan olarak geçerli dizini ve sistem ortamını ISO 27001 kontrollerine göre tarar:

```powershell
# Mevcut dizini tara (Konsol renkli çıktısı)
.\iso-guard.exe scan .

# Belirli bir projeyi veya dizini tara
.\iso-guard.exe scan C:\Projelerim\web-app

# Denetçiler (Auditors) için resmi Markdown denetim raporu üret
.\iso-guard.exe scan . --output report.md

# CI/CD otomasyonları ve SIEM için JSON formatında dışa aktar
.\iso-guard.exe scan . --output results.json
.\iso-guard.exe scan . --output json

# Ağ port denetimini de dahil et
.\iso-guard.exe scan . --network

# Harici YAML kural klasörü belirterek tara
.\iso-guard.exe scan . --policies policies/

# CI/CD Pipeline Kapısı: HIGH veya CRITICAL bulgu varsa 1 çıkış kodu ile hata ver
.\iso-guard.exe scan . --fail-on HIGH
```

### 2. Desteklenen Kuralları Listeleme (`list-rules`)
Kütüphanede kayıtlı ISO kontrollerini görüntüler:

```powershell
# Tüm kuralları listele
.\iso-guard.exe list-rules

# Sadece HIGH ve üzeri önem seviyesindeki kuralları göster
.\iso-guard.exe list-rules --severity HIGH

# JSON formatında listele
.\iso-guard.exe list-rules --format json
```

### 3. GitHub Depo ve Organizasyon Taraması (`scan-github`)
GitHub reposu veya organizasyonunu ISO 27001 kontrollerine göre tarar:

```powershell
# GitHub reposunu tara
.\iso-guard.exe scan-github owner/repo

# Token belirterek özel/şirket reposunu tara (Rate limit ve koruma kuralları için)
.\iso-guard.exe scan-github owner/repo --token ghp_yourPersonalAccessToken

# Tüm organizasyonu tara
.\iso-guard.exe scan-github org:my-organization

# JSON formatında dışa aktar
.\iso-guard.exe scan-github owner/repo --format json --output gh-audit.json
```

### 4. Sürüm Bilgisi (`version`)
```powershell
.\iso-guard.exe version
```

---

## 🛡️ Yerleşik ISO 27001:2022 Kontrolleri

| Kontrol No | Kural ID | Kategori | Önem | Açıklama |
| :--- | :--- | :--- | :---: | :--- |
| **A.8.12** | `ISO-A.8.12-SECRETS` | Technological | `CRITICAL` | Dizin içerisindeki açıkta kalan parola, API anahtarı ve `.env` dosyalarını denetler. |
| **A.8.24** | `ISO-A.8.24-PRIVATE-KEYS` | Technological | `HIGH` | Şifrelenmemiş özel anahtarların (`.key`, `.pem`, `id_rsa`) kaynak kodda saklanmasını engeller. |
| **A.8.9** | `ISO-A.8.9-PERMISSIONS` | Technological | `MEDIUM` | Yapılandırma ve şablon dosyalarında herkese yazma iznini (world-writable) denetler. |
| **A.8.9** | `ISO-A.8.9-ENV-SECRETS` | Technological | `HIGH` | Ortam değişkenlerinde açık metin hassas secret anahtarlarını kontrol eder. |
| **A.5.15** | `ISO-A.5.15-PRIVILEGES` | Organizational | `LOW` | Denetim ve çalıştırma süreçlerinin gereksiz root/yönetici yetkileriyle çalışmasını denetler. |
| **A.8.20** | `ISO-A.8.20-CLEARTEXT-PORTS`| Technological | `HIGH` | Telnet, FTP gibi açık metin protokollerin dinlediği portları tespit eder. |
| **A.8.7** | `ISO-A.8.7-UNEXPECTED-BINARIES`| Technological| `MEDIUM` | Kaynak dizinlerde izinsiz veya beklenmeyen derlenmiş ikili dosyaları (.exe, .dll, .so) kontrol eder. |

---

## ⚙️ Yapılandırma Dosyası (`iso-guard.yaml`)

Araç dizindeki `iso-guard.yaml` dosyasını otomatik olarak okur veya `--config /path/to/config.yaml` parametresi ile beslenebilir:

```yaml
profile: "iso-27001-2022"

target:
  path: "."
  type: "directory"
  exclude_dirs:
    - ".git"
    - "node_modules"
    - "vendor"

rules:
  # Harici YAML kural tanımlarının konumu
  policies_path: "policies"
  min_severity: "LOW"
  fail_on_severity: "HIGH"
  include: []
  exclude: []

scanners:
  enable_filesystem: true
  enable_system: true
  enable_network: false

report:
  format: "console"
  color: true
  verbose: false
```

---

## 📜 YAML Tabanlı Kural Motoru (Policy Engine)

Kod yazmaya gerek kalmadan harici YAML dosyaları üzerinden ISO 27001 kuralları tanımlanabilir ve işletilebilir.

### Örnek YAML Tanımı (`policies/iso27001-sample-rules.yaml`)

```yaml
version: "1.0"
policies:
  - id: "ISO-A.9.4.2"
    control_id: "A.5.17"
    title: "Parola Karmaşıklığı ve Asgari Uzunluk Politikası"
    description: "Yapılandırma dosyalarında tanımlanan parola politikasının en az 12 karakter olduğunu denetler."
    category: "Organizational Controls"
    severity: "HIGH"
    enabled: true
    remediation: "Parola asgari uzunluğunu en az 12 karakter olarak güncelleyin."
    spec:
      target_type: "file"
      match_files:
        - "*config*.yaml"
        - "*application*.properties"
      assertions:
        - type: "regex_match"
          pattern: "(?i)min[-_]?password[-_]?(len|length)?\\s*[:=]\\s*(\\d+)"
          min_value: 12
          message: "Parola asgari uzunluğu en az 12 karakter olmalıdır."
        - type: "disallow_patterns"
          patterns:
            - "(?i)password\\s*[:=]\\s*['\"]?(admin|123456|password|root)['\"]?"
          message: "Varsayılan/zayıf parola tanımı tespit edildi."

  - id: "ISO-A.8.28-BRANCH-PROTECTION"
    control_id: "A.8.28"
    title: "Kaynak Kod Branch Koruma ve Değişiklik Yönetimi Politikası"
    description: "Depoda CODEOWNERS veya onaylı CI/CD iş akışlarının varlığını denetler."
    category: "Technological Controls"
    severity: "HIGH"
    enabled: true
    remediation: "Depoya CODEOWNERS dosyası ekleyin ve doğrudan commit gönderimini kısıtlayın."
    spec:
      target_type: "git"
      alternative_files:
        - ".github/CODEOWNERS"
        - "CODEOWNERS"
        - ".github/workflows"
        - ".gitlab-ci.yml"
      assertions:
        - type: "file_exists"
          message: "Depo üzerinde kod sahipliği (CODEOWNERS) veya CI/CD iş akışı bulunmalıdır."
```

### Özel Politika Dosyalarını Çalıştırma
```powershell
# Özel bir politika dizinini veya dosyasını çalıştır
.\iso-guard.exe scan . --policies ./my-custom-policies/
```

---

## 🧩 Go Kodu ile Yeni Bir Kural Ekleme (Genişletilebilirlik)

`engine.RegisterRule` fonksiyonunu kullanarak doğrudan Go içerisinde yeni bir kural eklemek de mümkündür:

```go
package myrules

import "github.com/efekrbas/iso-guard/engine"

func init() {
    engine.RegisterRule(engine.Rule{
        ID:             "ISO-A.8.28-SECURE-CODING",
        ControlID:      "A.8.28",
        Title:          "Güvenli Kodlama Prensipleri",
        Description:    "Kaynak kodda güvensiz fonksiyon kullanımlarını denetler.",
        Category:       "Technological Controls",
        Severity:       engine.SeverityHigh,
        DefaultEnabled: true,
        Tags:           []string{"code_security", "sast"},
        Evaluate: func(ctx *engine.ScanContext) engine.RuleResult {
            return engine.RuleResult{
                Status:  engine.StatusPass,
                Message: "Güvensiz kod deseni tespit edilmedi.",
            }
        },
    })
}
```