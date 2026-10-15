# Vuln-Check-Net (Multi-Vendor Network CVE Audit Engine)

Công cụ đánh giá lỗ hổng bảo mật và kiểm toán cấu hình thiết bị mạng đa hãng (**Cisco ASA**, **Cisco IOS XE**, **Fortinet FortiOS**, **Palo Alto PAN-OS**).

---

## 1. Điểm Khác Biệt Cốt Lõi: Đánh Giá Tương Quan 2 Điều Kiện

Các máy quét CVE truyền thống chỉ đối chiếu phiên bản hệ điều hành (OS Version), dẫn đến **hàng loạt cảnh báo giả (False Positives)** đối với những tính năng mà quản trị viên **không hề bật** trên thiết bị.

**Vuln-Check-Net** loại bỏ hoàn toàn nhược điểm này bằng kiến trúc tương quan 2 điều kiện:

$$\text{Tình trạng} = \begin{cases} 
\mathbf{EXPLOITABLE} & \text{khi } (\text{Version affected}) \land (\text{Feature Precondition Enabled}) \\
\mathbf{MITIGATED} & \text{khi } (\text{Version affected}) \land (\text{Feature Precondition Disabled}) \\
\mathbf{NOT\_AFFECTED} & \text{khi } \neg(\text{Version affected})
\end{cases}$$

- **Điều kiện cần**: Phiên bản OS nằm trong dải bị ảnh hưởng bởi CVE.
- **Điều kiện đủ**: Tính năng dễ bị tổn thương (**HTTP Server / Web UI**, **WebVPN / SSL-VPN**, **SNMP**, **Telnet**, **Smart Install**, **AAA**) đang thực sự bật trong cấu hình running-config.
  - Nếu tính năng **bật**: Đánh giá rủi ro thực tế là `CRITICAL` hoặc `HIGH` (Đặc biệt cảnh báo đỏ nếu nằm trong **CISA KEV** hoặc chiến dịch **Ransomware**).
  - Nếu tính năng **tắt**: Đánh giá tình trạng là `MITIGATED` với mức rủi ro thực tế kéo giảm về `LOW` (không còn khả năng bị khai thác trực tiếp).

---

## 2. Thiết Bị & Hệ Điều Hành Hỗ Trợ

| Vendor | OS Family | Dải Phiên Bản Hỗ Trợ Phân Tích | Các Tính Năng Kiểm Toán Precondition |
| :--- | :--- | :--- | :--- |
| **Cisco** | Cisco ASA | 9.x, 8.x, FPR Series (e.g. `9.20(3)`, `9.18(4)22`) | `http_server`, `webvpn`, `ssl_vpn`, `snmp_server`, `ssh`, `telnet`, `aaa` |
| **Cisco** | Cisco IOS XE | 16.x, 17.x (e.g. `17.15.1a`, `16.10.1`) | `http_server` (Web UI), `snmp_server`, `smart_install` (vstack), `ssh` |
| **Fortinet** | Fortinet FortiOS | 6.x, 7.x (e.g. `v7.2.4`, `7.0.0`, `7.4.1`) | `ssl_vpn` (web portal), `http_server` (admin GUI), `snmp_server` |
| **Palo Alto** | PAN-OS | 8.x, 9.x, 10.x, 11.x (e.g. `10.2.3-h4`) | `ssl_vpn` (GlobalProtect), `http_server`, `aaa` (SAML) |

---

## 3. Hoạt Động 100% Offline (Air-Gapped Ready)

- **CISA KEV Local Seed**: File `data/cisa_kev_cache.json` lưu sẵn danh mục các CVE KEV thực tế phục vụ khai thác thiết bị mạng (ArcaneDoor, Akira Ransomware, Shadow Brokers EXTRABACON, Jaguar Tooth, XORtigate...).
- **NVD SQLite Local Cache**: Database `data/vuln_cache.db` lưu sẵn điểm số CVSS v3.1 và mô tả kỹ thuật chi tiết của tất cả CVE trong cơ sở tri thức.
- **Tùy chọn Online Update**: Hỗ trợ kết nối NVD REST API 2.0 (kèm `NVD_API_KEY` và exponential backoff) và cập nhật feed CISA KEV khi có Internet.

---

## 4. Cấu Trúc Dự Án

```
Network-VA/
├── data/
│   ├── cisa_kev_cache.json    # Cache & seed CISA Known Exploited Vulnerabilities
│   └── vuln_cache.db          # SQLite persistent cache lưu trữ thông tin CVE NVD
├── outputs/                   # Thư mục xuất báo cáo (Markdown, Excel, JSON)
├── src/
│   ├── __init__.py
│   ├── config.py              # Tham số cấu hình, URL, hằng số OS & Vendor
│   ├── version_utils.py       # Parser & chuẩn hóa dải phiên bản thiết bị mạng
│   ├── parser.py              # Bộ bóc tách running-config & metadata thiết bị
│   ├── fetcher_cisa.py        # Module quản lý cache CISA KEV Catalog
│   ├── fetcher_nvd.py         # Module quản lý cache SQLite NVD REST API
│   ├── rules.py               # Cơ sở tri thức 21+ CVE quy tắc Precondition
│   ├── engine.py              # CorrelationEngine đánh giá 2 điều kiện cần & đủ
│   ├── reporter.py            # Xuất báo cáo Markdown, Excel (openpyxl), JSON
│   └── tui/                   # Giao diện Terminal User Interface (Textual 7.0.0)
│       ├── __init__.py
│       └── app.py             # Ứng dụng VulnCheckApp TUI đa tab tương tác
├── tests/
│   ├── test_version.py        # Kiểm thử chuẩn hóa phiên bản & so sánh dải version
│   ├── test_parser.py         # Kiểm thử bóc tách metadata & features các hãng
│   ├── test_engine.py         # Kiểm thử logic phân loại EXPLOITABLE vs MITIGATED
│   ├── test_integration.py    # Kiểm thử tích hợp toàn diện trên cấu hình thực tế
│   └── test_tui.py            # Pilot Headless Tests giao diện Textual TUI
├── requirements.txt
├── run_scan.py                # Giao diện dòng lệnh CLI (Rich UI)
├── run_tui.py                 # Khởi chạy giao diện trực quan TUI độc lập
└── README.md
```

---

## 5. Giao Diện Terminal User Interface (TUI Interactive Console)

Công cụ tích hợp giao diện điều khiển dòng lệnh đồ họa trực quan (TUI) xây dựng trên nền tảng **Textual 7.0.0** và **Rich 14.3.1**, mang phong cách Trung tâm Điều hành An ninh mạng (SOC Cyber Deck).

### 5.1 Khởi chạy giao diện TUI
Bạn có thể khởi chạy TUI bằng một trong hai cách:
```bash
# Cách 1: Khởi chạy trực tiếp qua entrypoint TUI
python run_tui.py

# Cách 2: Khởi chạy qua lệnh subcommand tui
python run_scan.py tui

# Nạp sẵn file cấu hình ngay khi mở ứng dụng:
python run_tui.py "F:/WORK/NCS_Downloads/Network config/Firewall ASA1.txt"
python run_scan.py tui --file "F:/WORK/NCS_Downloads/cisco_ios_xe_sample_config.txt"
```

### 5.2 Các phím tắt điều khiển (Key Bindings)
| Phím tắt | Tác vụ | Mô tả |
| :--- | :--- | :--- |
| `Ctrl + Q` | **Thoát ứng dụng** | Đóng giao diện TUI an toàn |
| `Ctrl + S` | **Quét cấu hình** | Chuyển sang Tab 1 và thực hiện kiểm toán file cấu hình |
| `Ctrl + D` | **Tab Device Audit** | Mở bảng điều khiển kiểm toán thiết bị & running-config |
| `Ctrl + L` | **Tab Version Lookup** | Mở bảng tra cứu nhanh CVE theo dải phiên bản |
| `Ctrl + K` | **Tab CISA KEV** | Mở bảng tra cứu danh mục khai thác thực tế CISA KEV |
| `Ctrl + E` | **Xuất báo cáo** | Xuất đồng thời 3 định dạng (.md, .xlsx, .json) vào `outputs/` |

### 5.3 Các Tab Chức Năng Chính

#### Tab 1: Device Audit (`#tab-audit`)
- **Quick Samples Bar**: Thanh 7 nút bấm nạp nhanh các cấu hình mạng thực tế:
  - `[ASA 1]`: Cisco ASA 5500/Firepower (`Firewall ASA1.txt`)
  - `[IOS XE]`: Cisco Catalyst / ISR IOS XE (`cisco_ios_xe_sample_config.txt`)
  - `[FortiOS]`: Fortinet FortiGate (`fortigate_fortios_sample_config.txt`)
  - `[PAN-OS]`: Palo Alto Networks Next-Gen Firewall (`paloalto_panos_sample_config.txt`)
  - `[F5 BIG-IP]`: F5 BIG-IP LTM/ASM WAF (`f5_bigip_asm_waf_sample_config.txt`)
  - `[Arbor]`: NETSCOUT Arbor Sightline / TMS DDoS (`arbor_sightline_tms_sample_config.txt`)
  - `[Imperva]`: Imperva SecureSphere WAF (`imperva_waf_sample_config.txt`)
- **Device Metadata Card**: Hiển thị Hostname, Vendor, OS Family, Version, Model, Active Features (màu xanh lá) và Inactive Features.
- **Audit Metrics Summary**: 6 thẻ đếm trực quan: *Rules Tested*, *Version Matched*, *EXPLOITABLE (Đỏ đậm)*, *MITIGATED (Xanh ngọc)*, *In CISA KEV*, *Critical / High*.
- **Vulnerabilities DataTable**: Danh sách bảng lỗ hổng với phân loại màu sắc: `CVE ID`, `Title`, `Status`, `Real Risk`, `CVSS`, `In KEV`, `Precondition`.
- **Vulnerability Detail Panel**: Khi di chuyển con trỏ hoặc click dòng trên bảng:
  - Hiển thị đầy đủ CVE ID, Title, CVSS Score, Vector, KEV status.
  - Bằng chứng kiểm toán Precondition (Tính năng đang bật hay tắt trong cấu hình).
  - Khuyến nghị khắc phục & Lệnh cấu hình remediation (`Mitigation Playbook`).
  - Thông tin CISA KEV (Remediation Due Date, Mandatory Action, Known Ransomware Campaign).
- **Export Buttons**: Các nút `Export MD`, `Export Excel`, `Export JSON` lưu vào `outputs/` và gửi thông báo Toast (`notify`).

#### Tab 2: Fast CVE Lookup (`#tab-lookup`)
- Cho phép tra cứu lỗ hổng theo dải phiên bản mà không cần running-config hoàn chỉnh.
- Dropdown `Select` hỗ trợ tất cả các dòng thiết bị (Cisco ASA, Cisco IOS XE, Fortinet FortiOS, Palo Alto PAN-OS, F5 BIG-IP, NETSCOUT Arbor, Imperva SecureSphere).
- Hỗ trợ các nút Quick Presets nạp nhanh phiên bản thông dụng.
- Bảng hiển thị các CVE tiềm ẩn, điều kiện kích hoạt cần thiết và câu lệnh khắc phục.

#### Tab 3: CISA KEV Explorer (`#tab-kev`)
- Danh mục tra cứu CISA Known Exploited Vulnerabilities catalog.
- Thanh tìm kiếm thời gian thực theo mã CVE, tên hãng, tên sản phẩm hoặc từ khóa.
- Các nút lọc nhanh theo hãng (*Cisco*, *Fortinet*, *Palo Alto*, *F5*) hoặc chỉ lọc các CVE từng được sử dụng trong các chiến dịch **Ransomware**.
- Khung chi tiết hiển thị toàn bộ thời hạn khắc phục bắt buộc của cơ quan liên bang Mỹ (Due Date) và hành động bắt buộc (Required Action).

---

## 6. Hướng Dẫn Sử Dụng Dòng Lệnh (CLI Mode)

### 6.1 Cài đặt thư viện
```bash
pip install -r requirements.txt
```

### 6.2 Quét file cấu hình running-config
Quét cấu hình một thiết bị mạng và xuất báo cáo đa định dạng:
```bash
python run_scan.py scan --file "F:/WORK/NCS_Downloads/Network config/Firewall ASA1.txt" \
  --out-md outputs/ASA1_report.md \
  --out-xlsx outputs/ASA1_report.xlsx \
  --out-json outputs/ASA1_report.json
```

Quét toàn bộ thư mục chứa nhiều file cấu hình:
```bash
python run_scan.py scan --dir "configs/" --out-xlsx outputs/network_audit.xlsx
```

### 6.3 Tra cứu nhanh theo Vendor và Phiên bản (Lookup Mode)
```bash
python run_scan.py lookup --vendor Cisco --os "Cisco ASA" --version "9.20(3)"
python run_scan.py lookup --vendor Cisco --os "Cisco IOS XE" --version "17.3.1"
python run_scan.py lookup --vendor Fortinet --os "Fortinet FortiOS" --version "7.2.4"
python run_scan.py lookup --vendor "Palo Alto" --os "Palo Alto PAN-OS" --version "10.2.3-h4"
```

### 6.4 Cập nhật CISA KEV Catalog khi có Internet
```bash
python run_scan.py update-kev
```

---

## 7. Chạy Kiểm Thử Tự Động (Test Suites)

Toàn bộ test suite bao gồm 49+ tests (cả unit tests và pilot headless TUI tests) được viết bằng `pytest`:
```bash
pytest -v
```
