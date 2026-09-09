# rules/ — Snort3 대표 룰셋

프로젝트에서 설계한 탐지 로직을 **Snort3 문법으로 재구성한 대표 룰**입니다. 보고서에 기록된 **SID·메시지·시그니처·임계값**을 그대로 반영했으며, 실제 운영 룰의 전체 세트가 아니라 설계 의도를 보여주기 위한 예시입니다.

## 파일 구성 (SID 대분류 기준)

| 파일 | SID 범위 | 내용 |
|---|---|---|
| [`1-protocol.rules`](1-protocol.rules) | `1XXXXXX` | FTP · SMB · SSH · DHCP · SNMP · DNS 기본 프로토콜 오남용 |
| [`2-web-attack.rules`](2-web-attack.rules) | `2XXXXXX` | SQLi · Stored XSS · File Upload · IDOR · RLO · Open Redirect |
| [`3-network-attack.rules`](3-network-attack.rules) | `3XXXXXX` | Brute Force · ARP Spoofing |
| [`4-recon-scan.rules`](4-recon-scan.rules) | `4XXXXXX` | SYN/FIN/NULL/Xmas·Version·NSE·IP Protocol 스캔 |
| [`5-system-attack.rules`](5-system-attack.rules) | `5XXXXXX` | Reverse Shell · Shell Command · File Access |

## 룰에 쓰인 변수 (snort.lua `ips.variables` 가정)

```lua
HOME_NET      = '10.0.0.0/8'
EXTERNAL_NET  = '!$HOME_NET'
HTTP_SERVERS  = '[10.60.0.10, 10.60.0.11]'   -- VulnMart WS01/WS02
DHCP_SERVER   = '10.30.192.25'                -- 승인된 DHCP 서버
```

## 검증 방법

```bash
# 문법 검증 (룰 로드만 확인)
snort -c snort.lua -R 2-web-attack.rules --warn-all

# PCAP 리플레이로 탐지 확인
snort -c snort.lua -R rules/ -r attack_scn01.pcap -A alert_fast
```

## Alert / Drop 분배

같은 룰이라도 배치 위치(IDS/IPS)와 오탐 위험도에 따라 `alert` ↔ `drop`(또는 `reject`)으로 액션을 바꿔 운용합니다. 분배 기준은 [`docs/02-ids-snort3.md`](../docs/02-ids-snort3.md#룰셋-분배-정책--alert냐-drop이냐) 참고.
