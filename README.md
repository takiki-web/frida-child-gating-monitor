# frida-child-gating-monitor

Windows 환경에서 **Frida Child Gating**을 이용해 런처가 생성하는 자식 프로세스를 자동으로 추적하고, 지정한 프로세스에만 `ws2_32.dll`의 `send()` / `recv()` 후킹을 적용하는 예제입니다.

이 프로젝트는 특히 **처음 실행한 프로세스가 실제 작업을 계속 수행하지 않고, 새로운 프로세스를 생성한 뒤 종료되는 프로그램 구조**를 계측하기 위해 작성했습니다.

## 왜 이 기능이 필요한가?

일부 Windows 프로그램은 사용자가 실행한 최초 프로세스가 실제 기능을 계속 수행하지 않습니다.

예를 들어:

```text
launcher.exe
    │
    ├─ 로그인 / 초기화 / 업데이트
    │
    └─ worker.exe 생성
            │
            ├─ 실제 네트워크 통신
            ├─ 주요 기능 수행
            └─ launcher.exe 종료
```

이런 구조에서는 최초 프로세스에 Frida를 attach하더라도, 실제 작업을 수행하는 새로운 프로세스가 생성되면서 기존 세션만으로는 원하는 동작을 계속 관찰하기 어렵습니다.

```text
Frida attach
    ↓
launcher.exe
    ↓
worker.exe 생성
    ↓
launcher.exe 종료

worker.exe
    ↑
실제로 관찰해야 하는 프로세스
```

특히 Worker가 생성 직후 서버 연결, 인증, DLL 로딩, 초기 패킷 송수신 등을 수행한다면 PID를 확인한 후 수동으로 attach하는 방식으로는 초기 동작을 놓칠 수 있습니다.

이 프로젝트는 이 문제를 해결하기 위해 Frida의 **Child Gating**을 사용합니다.

```text
launcher.exe
    │
    ├─ regsvr32.exe
    │      └─ 관심 대상 아님 → resume
    │
    └─ worker.exe
           │
           ├─ child-added 감지
           ├─ attach
           ├─ Frida Script 로드
           ├─ ws2_32 hook
           └─ resume
```

즉, 새로운 프로세스가 생성되는 시점에 감지하고 원하는 Worker에 자동으로 instrumentation을 적용한 뒤 실행을 계속합니다.

## 이런 경우에 유용합니다

* 최초 실행 프로세스가 곧 종료되는 프로그램
* Launcher와 실제 Worker가 분리된 프로그램
* 실제 작업 프로세스가 매번 새로운 PID로 생성되는 프로그램
* Worker가 생성 직후 네트워크 통신을 시작하는 프로그램
* 수동 attach로 초기 통신이나 초기화 과정을 놓치는 경우
* 여러 child 중 특정 프로세스만 계측하고 싶은 경우
* Launcher → Worker → Helper처럼 여러 단계로 프로세스가 생성되는 경우

## 주요 기능

* Frida `spawn()`으로 대상 프로그램 실행
* `enable_child_gating()`을 이용한 child process 추적
* `child-added` 이벤트 기반 자동 계측
* Process whitelist 지원
* 관심 없는 child는 attach 없이 resume
* 지정한 Worker만 자동 attach
* `ws2_32.dll!send` / `recv` 관찰
* UTF-8 / CP949 문자열 디코딩
* 간단한 프레임 헤더 분석
* 요청 / 응답 로그 출력
* Frida 17.16.x 환경의 callback blocking을 피하기 위한 Thread 기반 처리

## 동작 구조
### Frida 17.8.2

```text
child-added
    │
    ├─ 일반 child → resume()
    │
    └─ Worker
          ├─ attach()
          ├─ Script Load
          └─ resume()
```

### Frida 17.16.3

```text
child-added
    │
    ├─ 일반 child
    │      └─ Thread → resume()
    │
    └─ Worker
           └─ Thread
                ├─ attach()
                ├─ Script Load
                └─ resume()
```

테스트한 Windows 환경에서는 Frida 17.8.2에서 child-added callback 내부의 직접 attach() / resume()이 정상 동작했지만, Frida 17.16.3에서는 blocking 현상이 관찰되어 별도 Thread에서 처리하도록 변경했습니다.

## 프로세스 필터링

계측하려는 프로세스를 `MONITOR_PROCS`에 등록합니다.

```python
MONITOR_PROCS = [
    "launcher.exe",
    "worker.exe",
    "agency.exe",
]
```

Python의 `on_child()` 단계에서 이름을 확인하므로 목록에 없는 프로세스에는 attach하지 않습니다.

```python
def is_target(path):

    name = (path or "").lower()

    return any(
        proc.lower() in name
        for proc in MONITOR_PROCS
    )

```

## 요구사항

* Windows
* Python 3
* Frida 17.16.3

## 실행 예시

관심 없는 child:

```text
[child-added] pid=16764 path=C:\Example\regsvr32.exe
    -> 대상 아님 (attach 생략)
    -> resume thread 시작 pid=16764
    -> resume OK pid=16764
```

계측 대상 Worker:

```text
[child-added] pid=32868 path=C:\Example\worker.exe
    -> TARGET FOUND
    -> attach thread 시작 pid=32868
    -> attach 시도 pid=32868
    -> attach OK pid=32868
    -> child gating OK pid=32868
[worker.exe] ws2_32 훅 장착 완료 (send=OK, recv=OK)
    -> instrument OK pid=32868
    -> resume OK pid=32868
```

네트워크 통신이 발생하면:

```text
[worker.exe] [14:32:11.142] [요청]
ID=1234-5678 seq=10 len=128 | ...

[worker.exe] [14:32:11.231] [응답]
ID=1234-5678 seq=10 len=256 | ...
```

형태로 확인할 수 있습니다.

## 향후 개선

* `WSASend` / `WSARecv`
* `sendto` / `recvfrom`
* 프로세스별 로그 저장
* Raw frame 저장
* Hexdump 출력
* Child Process Tree 출력
* DLL Load 추적
* CLI 기반 Target / Process 설정
* Frame Parser 모듈화

## Disclaimer

이 프로젝트는 Frida Child Gating 및 Windows 프로세스/네트워크 instrumentation 동작을 연구하고 학습하기 위한 예제입니다.

본인이 소유하거나 테스트 권한을 가진 시스템에서만 사용하십시오.
