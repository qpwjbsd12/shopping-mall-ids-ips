# 쇼핑몰 인프라 대상 IDS/IPS 탐지·차단 체계 구축

> 취약 쇼핑몰(VulnMart)을 대상으로 한 모의해킹 시나리오를 **Snort3 IDS**로 탐지하고, **pfSense + Suricata IPS**와 **서버 방화벽(iptables/firewalld/UFW)** 으로 차단하는 다계층(defense-in-depth) 보안관제 체계를 설계·구축했습니다.

![Snort](https://img.shields.io/badge/Snort-3.12.2-e74c3c)
![Suricata](https://img.shields.io/badge/Suricata-7.0.11-2ecc71)
![pfSense](https://img.shields.io/badge/pfSense-2.8.1-1f6feb)
![Firewall](https://img.shields.io/badge/iptables%20%7C%20firewalld%20%7C%20UFW-lightgrey)
![Role](https://img.shields.io/badge/Role-Purple%20Team%20(SOC)-8e44ad)

---

## 📌 한눈에 보기

| 항목 | 내용 |
|---|---|
| **프로젝트** | 쇼핑몰 인프라 구축 및 모의 해킹과 보안 솔루션 점검 (2차 팀 프로젝트) |
| **소속 / 기간** | 메가스터디 AI캠퍼스 정보보안 전문가 과정 · 2026.08.03 ~ 08.14 (2주) |
| **팀 구성** | 블루(네트워크·서버) / 퍼플(보안관제) / 레드(모의해킹) |
| **내 역할** | **퍼플팀 — Snort3 IDS 탐지 룰셋 설계, pfSense+Suricata IPS·서버 방화벽 구축** |
| **환경** | GNS3 격리 훈련망, 취약 쇼핑몰 웹앱 VulnMart (nginx · PHP · MariaDB) |
| **핵심 스택** | Snort 3.12.2, Suricata 7.0.11, pfSense 2.8.1, iptables/firewalld/UFW, rsyslog/syslog-ng, BPF, libpcap |

---

## 🎯 프로젝트 개요

실제 쇼핑몰을 겨냥한 사이버 공격이 **여러 취약점을 연계한 침투 형태**로 고도화되고 있습니다. 이 프로젝트는 개별 취약점을 단순 진단하는 데 그치지 않고, **레드팀이 실제 공격 체인을 재현 → 퍼플팀이 그 공격을 탐지·차단·분석**하는 공수(攻守) 검증 구조로 설계되었습니다.

```
[레드팀]  정찰 → 인증 우회 → 세션 탈취 → 개인정보·카드 유출 → 서버 제어권 탈취(RCE)
                              │  (동일 트래픽·로그)
                              ▼
[퍼플팀]  Snort3 IDS 탐지 ─→ pfSense/Suricata IPS 차단 ─→ 로그 상관분석·정오탐 판정
   (내 담당)     ●                     ●                        (팀 협업: ALPACA)
```

저는 이 구조에서 **"공격을 무엇으로, 어디서, 어떻게 탐지하고 막을 것인가"** 를 책임지는 **탐지·차단 엔지니어링(Detection Engineering)** 을 담당했습니다.

---

## 🛡️ 내가 담당한 부분

### 1. Snort3 기반 IDS 탐지 룰셋 설계
- 공격 유형을 **6개 대분류 SID 체계(1XXXXXX~6XXXXXX)** 로 표준화하고, 프로토콜·공격별로 룰을 세분류
- 레드팀 **4개 공격 시나리오(SCN-01~04)의 전 단계**에 대응하는 탐지 시그니처 작성
- IDS 3대(IDS01/02/03)를 구간별(웹하드 / 모니터링 / RedZone)로 역할 분리
- 단발 패킷 매칭을 넘어 **`detection_filter` 기반 임계·행위 탐지**(포트스캔·브루트포스·DHCP 플러딩)까지 구현

### 2. IPS(pfSense + Suricata)·서버 방화벽 구축
- **브리지(투명) 모드** IPS 3대를 재설계 없이 세그먼트 앞단에 삽입, 구간별 배치
- IDS 룰셋을 **오탐 위험도에 따라 Alert/Drop으로 재분배** — 구간별 DROP 차등 적용
- 서버별로 iptables/firewalld/UFW를 **역할에 맞게 차등 적용**, `기본 차단 + 화이트리스트` 원칙
- **아웃바운드 egress 통제**로 리버스 셸(4444·5555/tcp)을 차단해 침해 후 내부 확산·유출 방지

### 3. 운영 중 문제 해결
- Security Onion(PF_RING 패킷 누락, Barnyard2 병목)을 진단하고 **Snort3 자체 관제로 전환** 결정
- Flow 포화 시 O(n) 병목을 개선해 처리량 **2,254 → 120,784 flow/s (약 53.6배)**
- RDP ACK 통신을 스캔으로 오탐하던 `ACK_SCAN` 룰(오탐률 50%↑)을 상관분석 기반으로 **튜닝**

---

## 🧱 다계층 보안 아키텍처

접근통제(ACL) → 실시간 차단(IPS) → 행위 탐지(IDS) → 서버 보호(방화벽)로 이어지는 **다계층 방어**를 구성했습니다. 각 계층은 담당 범위와 조치 권한(차단/DROP/Alert)이 다릅니다.

![다계층 보안 정책 구조](assets/img/security-policy-layers.jpg)

| 계층 | 핵심 관점 | 조치 |
|---|---|---|
| Router / L3 ACL | 통신 경로(구간 접근 범위 제한) | 차단 |
| **IPS / Firewall (담당)** | 명확한 악성 트래픽 실시간 차단 | **DROP** |
| **Network IDS (담당)** | 공격·비정상 행위 탐지·분석 | **Alert** |
| Server firewalld / UFW (담당) | 호스트 서비스 포트·출발지 제한 | 차단 |
| TCP Wrapper / SELinux | 서비스·프로세스 접근 제어 | 차단 / DROP |

> 자세한 내용 → [`docs/01-architecture.md`](docs/01-architecture.md)

---

## 📚 문서

| 문서 | 내용 |
|---|---|
| [01. 아키텍처](docs/01-architecture.md) | 네트워크 구간·관제 아키텍처, IDS/IPS 배치, 다계층 방어 설계 |
| [02. Snort3 IDS 탐지 설계](docs/02-ids-snort3.md) | Snort3 전환 배경, SID 체계, 시나리오별 탐지 시그니처, 임계 탐지 |
| [03. IPS·서버 방화벽](docs/03-ips-firewall.md) | pfSense+Suricata 인라인 IPS, 구간별 DROP 차등, 서버 방화벽 egress 통제 |
| [04. 트러블슈팅·튜닝](docs/04-troubleshooting.md) | 패킷 누락·병목 진단, Flow 53.6배 성능 개선, 오탐 룰 튜닝 |
| [05. 검증·결과](docs/05-verification.md) | 구현도 평가(PP-01~20), 시나리오별 탐지 매트릭스, 한계·개선 |
| [rules/](rules/) | 문서화된 탐지 로직을 재구성한 **대표 Snort3 룰 예시** |

---

## 🔎 탐지 대상 — 레드팀 4개 공격 시나리오

| 시나리오 | 공격 | 내가 설계한 탐지 포인트 |
|---|---|---|
| **SCN-01** | SQLi 인증 우회 → 스키마 열거 → 개인정보 대량 탈취 | SQL 주석·항진식·`information_schema`·`UNION SELECT` 시그니처 |
| **SCN-02** | 저장형 XSS → 쿠폰 피싱 → 카드정보 스니핑 | `<script>`/`document.cookie` 탐지, 세션 IP 변경 상관분석 |
| **SCN-03** | 파일 업로드 → 리버스 셸 RCE | 확장자·Content-Type 불일치, `bash -i`·`/dev/tcp` 아웃바운드 |
| **SCN-04** | 로그인 브루트포스 계정 탈취 | `detection_filter` 60초 10회 임계 탐지, 평문 자격증명 노출 |

> 각 시나리오의 SID·시그니처 상세 → [`docs/02-ids-snort3.md`](docs/02-ids-snort3.md)

---

## 💡 이 프로젝트에서 배운 것

- **탐지는 시그니처가 전부가 아니다** — 단발 패킷 매칭(SQLi 문자열)과 임계·행위 기반 탐지(스캔·브루트포스)는 설계 방식이 다르며, 후자는 반드시 오탐 튜닝이 뒤따라야 한다.
- **IDS와 IPS는 같은 룰이라도 운용이 다르다** — IDS는 분석을 위해 넓게 Alert, IPS는 서비스 영향을 고려해 확정 시그니처만 Drop. 구간의 정상 트래픽 성격에 따라 차단 폭을 차등해야 한다.
- **경계 방어만으로는 부족하다** — WAF/IDS를 우회당해도 서버 아웃바운드 egress를 막으면 리버스 셸 연결 자체가 실패한다. 침해를 "막는 것"과 "확산을 끊는 것"은 다른 계층의 문제다.
- **도구는 검증하고 써야 한다** — Security Onion을 그대로 쓰지 않고 패킷 누락을 실측(tcpdump 대조)해 원인을 규명하고 대안을 선택한 경험.

---

*본 저장소는 학습용 격리 훈련망(GNS3, 사설 IP·더미 데이터)에서 수행한 결과물입니다. 실제 운영 자산·개인정보는 포함되어 있지 않습니다.*
