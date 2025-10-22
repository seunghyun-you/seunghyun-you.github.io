**Table of Contents**
---
- [**Table of Contents**](#table-of-contents)
- [Cilium](#cilium)
  - [1. Cilium 구성요소](#1-cilium-구성요소)
    - [1.1 Cilium 구성요소](#11-cilium-구성요소)
    - [1.2 Cilium Agent가 제공하는 디버깅 툴](#12-cilium-agent가-제공하는-디버깅-툴)
  - [2. 네트워크 구성 정보 : _cilium host, cilium net, cilium health_](#2-네트워크-구성-정보--cilium-host-cilium-net-cilium-health)
    - [2.1 네트워크 인터페이스 구조](#21-네트워크-인터페이스-구조)
    - [2.2 Cilium Network Interface 조회](#22-cilium-network-interface-조회)
  - [3. eBPF를 이용한 Packet Flow (eBPF Datapath)](#3-ebpf를-이용한-packet-flow-ebpf-datapath)
    - [3.1 같은 노드에 배치된 Pod 간의 통신 경로](#31-같은-노드에-배치된-pod-간의-통신-경로)
    - [3.2 Pod에서 외부로 나가는 트래픽 통신 경로](#32-pod에서-외부로-나가는-트래픽-통신-경로)
    - [3.3 Pod 내부로 들어오는 트래픽 통신 경로](#33-pod-내부로-들어오는-트래픽-통신-경로)
    - [3.4 Packet Flow 과정에 사용되는 주요 eBPF Program](#34-packet-flow-과정에-사용되는-주요-ebpf-program)
- [Cilium Networking](#cilium-networking)
  - [1. Cluster 내부 통신에 사용되는 Network Mode : _Encapsulation(VxLAN, Geneve), Native/Direct_](#1-cluster-내부-통신에-사용되는-network-mode--encapsulationvxlan-geneve-nativedirect)
    - [1.1 Encapsulation Routing Mode (Default)](#11-encapsulation-routing-mode-default)
    - [1.2 Native Routing Mode](#12-native-routing-mode)
    - [1.3 Native Routing Mode 파드간 통신 테스트](#13-native-routing-mode-파드간-통신-테스트)
  - [2. 클러스터 외부로 향하는 패킷 처리를 위한 Maquerading 처리](#2-클러스터-외부로-향하는-패킷-처리를-위한-maquerading-처리)
    - [2.1 Cluster와 같은 네트워크에 있지만 Cluster에 Join 되지 않은 VM 과의 통신 테스트](#21-cluster와-같은-네트워크에-있지만-cluster에-join-되지-않은-vm-과의-통신-테스트)
    - [2.2 Cluster 외부의 다른 네트워크 대역(10.0.0.0/16)에 있는 네트워크와의 통신 테스트](#22-cluster-외부의-다른-네트워크-대역1000016에-있는-네트워크와의-통신-테스트)
    - [2.3 Cluster 외부의 다른 네트워크 대역(10.0.0.0/16)과 Masquerade 없이 통신하도록 설정하는 방법](#23-cluster-외부의-다른-네트워크-대역1000016과-masquerade-없이-통신하도록-설정하는-방법)
  - [3. 네트워크 엔드포인트(컨테이너/LB) IP 관리를 위한 IPAM (IP Address Management)](#3-네트워크-엔드포인트컨테이너lb-ip-관리를-위한-ipam-ip-address-management)
    - [3.1 Kubernetes Host Scope](#31-kubernetes-host-scope)
    - [3.2 Cluster Scope IPAM (Default)](#32-cluster-scope-ipam-default)
    - [3.3 Multi Pool](#33-multi-pool)
    - [3.4 Load Balaner / Egress IPAM](#34-load-balaner--egress-ipam)

## Cilium

<p align=center><img src="./_image/cilium.png" title="출처: Getting started with Cilium for Kubernetes networking and observability" width="60%"></p>

- Cilium은 eBPF 기술을 이용해서 쿠버네티스의 네트워크와 보안 기능을 구현한 쿠버네티스의 CNI Plugin 이다.

- eBPF는 리눅스 커널의 소스코드 변경 없이 커널 내부에서 샌드박스 프로그램을 실행시켜 커널의 기능을 효율적으로 확장시킬 수 있다. [ [BLOG](https://zerotay-blog.vercel.app/4.RESOURCE/KNOWLEDGE/OS/eBPF/) ]

<br>

### 1. Cilium 구성요소

#### 1.1 Cilium 구성요소

<p align=center><img src="./_image/cilium_architecture_03.png" width="60%"></p>

##### Cilium Operator

- Deployment로 배포되어 쿠버네티스 클러스터 수준에서 처리해아 하는 작업(CRD, IPAM 등)을 관리한다.

- Operator는 네트워킹 과정에 깊게 관여하지 않아 일시적인 중단에도 클러스터 동작에 큰 영향을 미치지 않는다.

  - IPAM Pool의 고갈 시 신규 IPAM Pool을 노드에 할당해야 하는데,

  - Operator의 장애로 신규 IPAM Pool 할당이 안될 경우 신규 Pod 생성이 실패한다.

##### Cilium CNI Plug-in (Node Level 작업)

- Pod 생성/삭제/주기적인 상태 확인 시 마다 Container Runtime에 의해 실행되면서 네트워크 구성(가상 인터페이스 구성, IP 할당/해제 등) 작업을 수행한다.

- Operator, Agent, Envoy와 같이 컨테이너로 동작하지 않고 필요할 때만 Container Runtime에 의해 실행된다.

- Binary 파일(`/opt/cni/bin/cilium-cni`, `/etc/cni/net.d/05-cilium.conflist`)로 각 노드에서 관리된다.

##### Cilium Agent (Kernel Level 작업, L3-4 계층)

- 데몬셋(DeamonSet)으로 배포되어 각 노드에서 Pod로 실행된다.

- Cilium Agent는 eBPF Program & MAP 로드, Cilium CNI Plug-in 설치, 쿠버네티스 상태 모니터링을 수행한다.

  - eBPF Program과 eBPF MAP을 커널에 Load 하고 관리한다. 

    - eBPF Program : 커널에서 발생시키는 이벤트(Hook Point)에 의해 실행되며, 네트워킹, 네트워크 정책 시행, 서비스 부하분산 등의 네트워크 기능을 수행한다.

    - eBPF MAP : eBPF Program이 사용하는 커널 내부에 구성되는 데이터 저장소다. User Space에서 MAP에 있는 데이터를 조회할 수도 있다.

  - Cilium CNI Plug-in Binary 파일을 노드에 설치하여 전반적인 네트워크 구성의 기능을 제공한다.

  - API Server와 통신하면서 쿠버네티스 리소스의 상태를 모니터링한다. 변경 사항이 발생하면 eBPF MAP을 업데이트 한다.

##### Envoy Proxy (UserSpace 작업, L7 계층)

- 데몬셋(DeamonSet)으로 배포되어 각 노드에서 Pod로 실행된다.

- Cilium L7 계층 관련 기능(Ingress, Gateway API, L7 Network Policies 등)을 사용하는 경우, Envoy Proxy를 통해 라우팅된다.

- HTTP 트래픽 제어, L7 Network Policy 시행, 정교한 라우팅 정책 관리와 같은 L7 기반 동적 라우팅/보안 기능을 제공한다.

> [!TIP]
> - Cilium에서 L3~4 계층의 트래픽은 Kernel의 eBPF Program으로 관리하고, L7 계층의 트래픽 처리는 Envoy에 위임는 구조로 동작한다.
> - 이러한 구조로 인해 MetalLB의 지원 없이 직접 LB, Ingress의 External IP 할당을 관리할 수 있다.
> - Envoy는 Ingress 라우팅 규칙 관리, L7 계층 Network Policy 등을 구현하고, Ingress의 External IP에 대한 L2 announcement, BGP 처리는 eBPF에서 처리한다.

<br>

#### 1.2 Cilium Agent가 제공하는 디버깅 툴

- Cilium Agent에는 관리용 CLI 두 가지(`cilium-dbg`, `bpftool`)를 제공한다.

  - cilium-dbg : Cilium 구성과 관련된 일반 적인 상태 정보, 정책, 서비스 목록 등을 확인하는데 사용한다.

  - bpftool : eBPF 수준의 디버깅이 필요한 경우 사용되는 도구로 커널에 로드된 eBPF 프로그램 목록, MAP 목록 조회 등에 사용한다.

- Cilium Agent Pod 내에서 실행할 수 있지만 `kubectl` 명령을 사용할 수 있는 노드(Control)에서 각 노드의 Cilium Agent를 통해 툴을 사용하도록 단축키를 지정한다.

  ```bash
  # /ect/profile
  export CILIUMPOD0=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=cilium-ctr -o jsonpath='{.items[0].metadata.name}')
  export CILIUMPOD1=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=cilium-w1 -o jsonpath='{.items[0].metadata.name}')
  export CILIUMPOD2=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=cilium-w2 -o jsonpath='{.items[0].metadata.name}')
  alias c0="kubectl exec -it $CILIUMPOD0 -n kube-system -c cilium-agent -- cilium"
  alias c1="kubectl exec -it $CILIUMPOD1 -n kube-system -c cilium-agent -- cilium"
  alias c2="kubectl exec -it $CILIUMPOD2 -n kube-system -c cilium-agent -- cilium"
  alias c0bpf="kubectl exec -it $CILIUMPOD0 -n kube-system -c cilium-agent -- bpftool"
  alias c1bpf="kubectl exec -it $CILIUMPOD1 -n kube-system -c cilium-agent -- bpftool"
  alias c2bpf="kubectl exec -it $CILIUMPOD2 -n kube-system -c cilium-agent -- bpftool"
  ```

  ```bash
  source /etc/profile
  ```

<br>

### 2. 네트워크 구성 정보 : _<span style="font-size: smaller; color: Aquamarine;">cilium host, cilium net, cilium health</span>_

#### 2.1 네트워크 인터페이스 구조

<p align=center><img src="./_image/cilium_interface_01.png" width="40%"></p>

##### cilium_host

- Cilium이 관리하는 호스트 네트워크 인터페이스다.

- Pod와 호스트 간의 통신, Pod와 Cluster 외부 네트워크 간의 연결에 사용된다. (Pod CIDR 대역 IP가 할당된다.)

- 외부에서 들어오는 패킷을 Pod로 전달하는 Reverse NAT 기능을 포함한다.

##### cilium_net

- cilium_host와 연결되는 veth pair 인터페이스다. (IP가 할당되지 않는다.)

- Cluster 내부에 배포된 Pod 간의 통신(보안 정책 적용, 패킷 필터링, 네트워크 성능 측정 등)을 처리한다.

##### cilium_health (lxc_health)

- Cilium Agent가 Cluster의 상태와 Container와의 통신 가능 여부를 확인하기 위해 사용하는 인터페이스다.

- PodCIDR 대역의 IP를 할당 받아서 사용하는데, 쿠버네티스에 의해 Pod로 생성된 리소스가 아니고 Cilium Agent에 의해 만들어지는 veth 인터페이스라서 kubectl로 정보를 조회할 수 없다.

##### lxcxxxx

- Pod에 할당되는 eth 인터페이스와 맵핑되는 가상 인터페이스다.

- 호스트 노드에서 IP 값은 조회되지 않지만 실제로는 Pod가 사용할 PodCIDR 대역의 IP가 할당되어 있다.

<br>

#### 2.2 Cilium Network Interface 조회

- control 노드에서 인터페이스의 목록을 확인해보면 cilium net, cilium host, lxc_health, lxcxxxxx 등의 인터페이스를 볼 수 있다.

  ```bash
  $ ip -c -br addr show
  lo                      UNKNOWN        127.0.0.1/8 ::1/128 
  eth0                    UP             10.0.2.15/24 metric 100 fd17:625c:f037:2:a00:27ff:fe6b:69c9/64 fe80::a00:27ff:fe6b:69c9/64 
  eth1                    UP             192.168.10.100/24 fe80::a00:27ff:fe30:52ea/64 
  cilium_net@cilium_host  UP             fe80::c82f:a2ff:fe04:7075/64 
  cilium_host@cilium_net  UP             172.20.2.28/32 fe80::30a8:dcff:fe03:da79/64 
  lxc_health@if6          UP             fe80::b0f3:9dff:fe38:f6f8/64 
  lxc72aa2e79d206@if8     UP             fe80::343b:39ff:fe72:d95d/64 
  ```

  - control 노드에서는 `lxc_health`, `lxc72aa2e79d206@if8` 인터페이스의 IP 정보는 직접 확인할 수 없다.

  - Interface에 할당된 상세 정보를 조회할 때는 cilium 에서 제공하는 cli(ciliu-dbg)를 이용해 조회할 수 있다.

- Interface 정보 상세 조회

  - cilium cli를 이용해서 control 노드에 할당되어 있는 IP 정보를 검색하면 다음과 같이 3개를 사용하고 있다는 것을 확인할 수 있다.

    ```bash
    $ c0 status --verbose | grep -A3 "Allocated"
    Allocated addresses:
    172.20.2.28 (router)
    172.20.2.5 (health)
    172.20.2.97 (default/curl-pod)
    ```

    - `router`와 `health`는 노드마다 Default로 생성되는 IP 정보다. 그 이외의 IP는 Pod의 수 만큼 추가로 할당된다.

    - Pod가 많지 않을 때는 이름을 보고 health 또는 파드의 Interface를 추정해볼 수 있지만 많을 경우 제한된다.

  - 먼저 `health` 인터페이스의 IP가 실제 control 노드에서 봤던 `lxc_health@if6` 인터페이스와 맵핑된 정보인지 확인하는 방법은 `ENDPOINT_ID` 조회 → `ENDPOINT`의 세부정보 조회를 통해 확인할 수 있다.

  - cilium에서는 각 endpoint(interface or ip address) 마다 `ENDPOINT_ID`를 할당하는데 해당 정보를 cilium cli로 조회한다.

    ```bash
    $ c0 endpoint list | grep 172.20.2.5
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                                                  IPv6   IPv4          STATUS   
               ENFORCEMENT        ENFORCEMENT 
    8          Disabled           Disabled          4          reserved:health                                                                     172.20.2.5    ready
    ```

  - `172.20.2.5(health)` IP에 할당 된 `ENDPOINT_ID`를 이용해서 해당 `ENDPOINT`의 세부 정보를 조회하면 control 노드에서 보았던 Interface Name, MAC 주소를 확인할 수 있다.

    ```bash
    $ c0 endpoint get 8 | grep -A11 networking
    "networking": {
      "addressing": [
        {
          "ipv4": "172.20.2.5",
          "ipv4-pool-name": "default"
        }
      ],
      "host-mac": "b2:f3:9d:38:f6:f8",
      "interface-index": 7,
      "interface-name": "lxc_health",
      "mac": "de:a9:ab:a9:a4:b4"
    },
    ```

    ```bash
    $ ip -c addr show lxc_health
    7: lxc_health@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
        link/ether b2:f3:9d:38:f6:f8 brd ff:ff:ff:ff:ff:ff link-netnsid 0
        inet6 fe80::b0f3:9dff:fe38:f6f8/64 scope link 
          valid_lft forever preferred_lft forever
    ```

  - 같은 방법으로 Pod와 연결된 `lxc72aa2e79d206@if8` 인터페이스의 정보를 상세 조회하면 control 노드에 배포된 `curl-pod`의 Interface Name, IP, MAC 주소를 확인할 수 있다.

    - control 노드에서 사용중인 IP 정보 조회

      ```bash
      $ c0 status --verbose | grep -A3 "Allocated"
      Allocated addresses:
      172.20.2.28 (router)
      172.20.2.5 (health)
      172.20.2.97 (default/curl-pod)
      ```

    - `curl-pod`의 IP로 `ENDPOINT_ID` 조회

      ```bash
      $ c0 endpoint list | grep 172.20.2.97
      ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                                                  IPv6   IPv4          STATUS   
                 ENFORCEMENT        ENFORCEMENT 
      190        Disabled           Disabled          47080      k8s:app=curl                                                                        172.20.2.97   ready
      ```

    - `172.20.2.97` IP에 할당 된 `ENDPOINT_ID`를 이용해서 해당 `ENDPOINT`의 세부 정보를 조회

      ```bash
      $ c0 endpoint get 190 | grep -A12 networking
      "networking": {
        "addressing": [
          {
            "ipv4": "172.20.2.97",
            "ipv4-pool-name": "default"
          }
        ],
        "container-interface-name": "eth0",
        "host-mac": "36:3b:39:72:d9:5d",
        "interface-index": 9,
        "interface-name": "lxc72aa2e79d206",
        "mac": "86:20:27:47:66:28"
      },
      ```

- Pod에서 Router로 사용하고 있는 IP의 정보 조회

  - cilium cli을 통해 control 노드에 할당되어 있는 IP의 정보를 검색하면 `router` 항목을 확인할 수 있다.

    ```bash
    $ c0 status --verbose | grep -A3 "Allocated"
    Allocated addresses:
    172.20.2.28 (router)
    172.20.2.5 (health)
    172.20.2.97 (default/curl-pod)
    ```

  - 이 인터페이스는 control 노드에 할당된 `cilium_host` 인터페이스의 IP와 같은 값이 할당되어 있다.

    ```bash
    $ ip -c -br addr show | grep cilium_host
    cilium_host@cilium_net UP             172.20.2.28/32 fe80::30a8:dcff:fe03:da79/64
    ```

  - `ENDPOINT_ID` 값을 이용해서 `ENDPOINT`의 세부 정보를 조회해도 실제 인터페이스에 할당된 이름이 `cilium_host`임을 확인할 수 있다.

    - router의 세부 정보 조회 시 `cilium_host`의 IP가 같이 표기되지 않기 때문에 `reserved:host` LABELS이 할당된 항목의 `ENDPOINT_ID`를 사용해야 한다.

      ```bash
      $ c0 endpoint list
      ...
      ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                                              IPv6   IPv4          STATUS   
                ENFORCEMENT        ENFORCEMENT                                                                                                                
      240        Disabled           Disabled          1          k8s:node-role.kubernetes.io/control-plane                                                     ready   
                                                                 k8s:node.kubernetes.io/exclude-from-external-load-balancers                                           
                                                                 reserved:host     
      ```

    - `ENDPOINT` 세부 정보 조회

      ```bash
      $ c0 endpoint get 240 | grep -A6 networking
      "networking": {
        "addressing": [
          {}
        ],
        "host-mac": "32:a8:dc:03:da:79",
        "interface-name": "cilium_host",
        "mac": "32:a8:dc:03:da:79"
      },
      ```

  - 그리고 실제로 이 IP는 control 노드에 배포된 Pod의 routing 정보를 조회 했을 때 default gateway로 사용되고 있는 것을 확인할 수 있다.

    ```bash
    $ kubectl exec -it curl-pod -- ip -c route 
    default via 172.20.2.28 dev eth0 mtu 1500 
    172.20.2.28 dev eth0 scope link 
    ```

<br>

### 3. eBPF를 이용한 Packet Flow (eBPF Datapath)

- `L7 Network Policy`, `Encryption`, `Network Mode` 설정이 적용된 경우 점선으로 표시된 항목들까지 통신 경로에 추가 된다.

- 별도로 활성화한 기능이나 정책이 없을 경우 Pod의 `lxc` 인터페이스에서 패킷이 출발하는 순간 커널의 TCX(Traffic Control eXpress) Hook을 통해 eBPF 프로그램(`bpf_lxc`, `bpf_host`)이 트리거 된다.

- 이 때 네트워크 트래픽은 커널 내부의 eBPF 프로그램에 의해서 정책이 평가되고, 평가 결과에 따라서 Flow가 결정된다.

#### 3.1 같은 노드에 배치된 Pod 간의 통신 경로

<p align=center><img src="./_image/packet_flow_endpoint_to_endpoint.png" title="출처: Cilium Documentation - Networking.eBPF_Datapath.Life_of_a_Packet" width="90%"></p>

<br>

#### 3.2 Pod에서 외부로 나가는 트래픽 통신 경로

<p align=center><img src="./_image/packet_flow_egress_from_endpoint.png" title="출처: Cilium Documentation - Networking.eBPF_Datapath.Life_of_a_Packet" width="90%"></p>

<br>

#### 3.3 Pod 내부로 들어오는 트래픽 통신 경로

<p align=center><img src="./_image/packet_flow_inress_from_endpoint.png" title="출처: Cilium Documentation - Networking.eBPF_Datapath.Life_of_a_Packet" width="90%"></p>

<br>

#### 3.4 Packet Flow 과정에 사용되는 주요 eBPF Program

##### 3.4.1 Pod Interface에 할당되는 eBPF Program 조회

- 실행되는 eBPF 프로그램(Component)명은 노란색 박스에 표시되는데, 이 프로그램들은 `cilium-agent` 내부에 C언어 파일로 `/var/lib/cilium/bpf` 폴더에 존재한다.
  
- 이 코드에 대한 내용은 Cilium GitHub 문서에서도 확인할 수 있다. [ [LINK](https://github.com/cilium/cilium/tree/main/bpf) ]

  ```bash
  # /var/lib/cilium/bpf
  $ ls -al
  total 336
  drwxr-xr-x 1 root root  4096 Jul 16 10:05 .
  drwxr-x--- 1 root root  4096 Jul 28 14:05 ..
  -rw-r--r-- 1 root root   420 Jul 16 10:05 COPYING
  -rw-r--r-- 1 root root  1296 Jul 16 10:05 LICENSE.BSD-2-Clause
  -rw-r--r-- 1 root root 18012 Jul 16 10:05 LICENSE.GPL-2.0
  -rw-r--r-- 1 root root 20261 Jul 16 10:05 Makefile
  -rw-r--r-- 1 root root  3533 Jul 16 10:05 Makefile.bpf
  -rw-r--r-- 1 root root  2945 Jul 16 10:05 bpf_alignchecker.c
  -rw-r--r-- 1 root root 58666 Jul 16 10:05 bpf_host.c
  -rw-r--r-- 1 root root 76153 Jul 16 10:05 bpf_lxc.c       # lxcxxx interface를 지날 때 트리거 되는 eBPF 프로그램
  -rw-r--r-- 1 root root  2797 Jul 16 10:05 bpf_network.c
  -rw-r--r-- 1 root root 25289 Jul 16 10:05 bpf_overlay.c
  -rw-r--r-- 1 root root 31334 Jul 16 10:05 bpf_sock.c
  -rw-r--r-- 1 root root  1424 Jul 16 10:05 bpf_wireguard.c
  -rw-r--r-- 1 root root  9064 Jul 16 10:05 bpf_xdp.c
  drwxr-xr-x 6 root root  4096 Jul 16 10:05 complexity-tests
  drwxr-xr-x 2 root root  4096 Jul 16 10:05 custom
  -rw-r--r-- 1 root root  1870 Jul 16 10:05 ep_config.h
  -rw-r--r-- 1 root root   517 Jul 16 10:05 filter_config.h
  drwxr-xr-x 1 root root  4096 Jul 16 10:05 include
  drwxr-xr-x 2 root root  4096 Jul 16 10:05 lib
  -rw-r--r-- 1 root root   404 Jul 16 10:05 netdev_config.h
  -rw-r--r-- 1 root root 10753 Jul 16 10:05 node_config.h
  drwxr-xr-x 4 root root  4096 Jul 16 10:05 tests
  ```

- Pod의 인터페이스 마다 할당되는 eBPF 프로그램의 함수는 `Pod Interface 정보 조회` → `할당된 eBPF Program ID 조회` → `프로그램 내 함수명 조회` 순으로 확인할 수 있다.

  - Pod Interface 정보 조회

    - Pod 조회

      ```bash
      $ kubectl get po -owide
      NAME                      READY   STATUS    RESTARTS        AGE   IP             NODE         NOMINATED NODE   READINESS GATES
      curl-pod                  1/1     Running   1 (4h34m ago)   14h   172.20.2.244   cilium-ctr   <none>           <none>
      webpod-697b545f57-5fmfp   1/1     Running   0               14h   172.20.0.97    cilium-w1    <none>           <none>
      webpod-697b545f57-g9c5f   1/1     Running   0               14h   172.20.1.38    cilium-w2    <none>           <none>
      ```

    - Pod의 ENDPOINT 정보 조회

      ```bash
      $ c0 endpoint list | grep 172.20.2.244
      ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])        IPv6   IPv4           STATUS   
                ENFORCEMENT        ENFORCEMENT
      4          Disabled           Disabled          47080      k8s:app=curl                              172.20.2.244   ready
      ```

    - Pod의 Interface Name 조회

      ```bash
      $ c0 endpoint get 4 | grep -A11 networking
            "networking": {
              "addressing": [
                {
                  "ipv4": "172.20.2.244",
                  "ipv4-pool-name": "default"
                }
              ],
              "container-interface-name": "eth0",
              "host-mac": "12:73:95:0d:4e:56",
              "interface-index": 9,
              "interface-name": "lxc49adfa975abf",
              "mac": "4e:22:88:88:7d:20"
      ```

  - Pod의 Interface에 적용된 eBPF 프로그램을 조회하면 `cil_from_container`, `cil_to_container` 함수 이름을 확인할 수 있다.

    ```bash
    $ c0bpf net show | grep lxc49adfa975abf
    lxc49adfa975abf(9) tcx/ingress cil_from_container prog_id 1143 link_id 23 
    lxc49adfa975abf(9) tcx/egress cil_to_container prog_id 1149 link_id 24
    ```

    - `cil_from_container` : Pod에서 나가는 트래픽(egress)에 대한 정책을 평가하고 적용한다.

    - `cil_to_container` : Pod로 들어오는 트래픽(ingress)에 대한 정책을 평가하고 적용한다.

##### 3.4.2 Pod로 들어오는 트래픽에 사용되는 eBPF Program 확인

- Cilium Agent 접속 후 `/var/lib/cilium/bpf/bpf_lxc.c` 파일을 grep으로 `cil_to_container()` 함수를 조회하면 세부 내용을 확인할 수 있다.

  ```bash
  $ grep -n -A160 "cil_to_container" /var/lib/cilium/bpf/bpf_lxc.c
  2335:int cil_to_container(struct __ctx_buff *ctx)
  2336-{
  ...
  2450-
  2451-BPF_LICENSE("Dual BSD/GPL");
  ```

- `cil_to_container()` 함수 내부 코드는 네트워크 정책 평가를 진행한 후 모두 통과 시 컨테이너로 트래픽을 Redirecting 한다.

  - L7 트래픽을 처리해야 할 경우에는 `tail_call_egress_policy()` 함수를 통해 네트워크 정책이 적용된다. 

    ```c
    #if defined(ENABLE_L7_LB)
      ...
        ret = tail_call_egress_policy(ctx, lxc_id);
        return send_drop_notify(ctx, lxc_id, sec_label, LXC_ID,
              ret, METRIC_INGRESS);
      }
    #endif
    ```

  - 호스트 방화벽 정책 적용이 필요한 경우 `tail_call_policy()` 함수를 통해 정책이 적용된다.

    ```c
    #if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)
      if (identity == HOST_ID) {
        ...
        ret = tail_call_policy(ctx, CONFIG(host_ep_id));
        return send_drop_notify(ctx, identity, sec_label, LXC_ID,
              DROP_HOST_NOT_READY, METRIC_INGRESS);
      }
    #endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */
    ```

  - 그 다음 프로토콜의 종류에 따라서 다르게 처리하기 위한 switch문이 있다.

    ```c
    	switch (proto) {
    #if defined(ENABLE_ARP_PASSTHROUGH) || defined(ENABLE_ARP_RESPONDER)
      case bpf_htons(ETH_P_ARP):
        ret = CTX_ACT_OK;
        break;
    #endif
    #ifdef ENABLE_IPV6
      case bpf_htons(ETH_P_IPV6):
        sec_label = SECLABEL_IPV6;
        ctx_store_meta(ctx, CB_SRC_LABEL, identity);
        ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_CT_INGRESS, &ext_err);
        break;
    #endif /* ENABLE_IPV6 */
    #ifdef ENABLE_IPV4
      case bpf_htons(ETH_P_IP):
        sec_label = SECLABEL_IPV4;
        ctx_store_meta(ctx, CB_SRC_LABEL, identity);
        ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_CT_INGRESS, &ext_err);
        break;
    #endif /* ENABLE_IPV4 */
      default:
        ret = DROP_UNKNOWN_L3;
        break;
      }
    ```

  - 여기에서 마지막으로 `tail_call_internal()` 함수가 다음 작업 처리를 이어서 처리할 함수로 점프한다.

  - eBPF에서 `tail_call()` 함수는 eBPF Program이 다른 eBPF Program을 호출해서 작업을 이어서 진행할 때 사용한다. [ [BLOG](https://www.ebpf.top/en/post/bpf2pbpf_tail_call/#6-summary) ]

    - cilium에서 사용되는 `tail_call()`은 `/var/lib/cilium/bpf/lib/tailcall.h`, `/var/lib/cilium/bpf/include/bpf/tailcall.h` 파일에서 `tail_call_static()` 함수로 정의 되어 있다.

    - 파라미터로 ctx_ptr(packet context pointer), BPF Program이 담긴 Array 유형의 MAP, 호출할 eBPF Program의 Index 값을 가지고 호출한다.

  - `tail_call_internal()` 함수 이후에는 커널 내부의 레지스트리 값, cilium이 유지하는 Program Index 값의 정보 확인이 제한되어 호출되는 함수를 확인하기 어렵다.

  - 그대신 최종적으로 Pod로 트래픽이 들어오게 되는 결정적인 역할을 하는 eBPF 프로그램은 cilium cli를 통한 트래픽 모니터링, hubble(cilium이 제공하는 관측툴)을 이용해 tracemessage를 이용해 어떤 프로그램이 사용되었는지 추정해볼 수 있다.

    - cilium cli 이용 ICMP 트래픽 모니터링 결과 : tracemessage = `to-endpoint`

      ```bash
      # curl-pod to netshoot-pod ping test
      $ c0 monitor --related-to=1169 -vv
      Listening for events on 2 CPUs with 64x4096 of shared memory
      Press Ctrl-C to quit
      ------------------------------------------------------------------------------
      time="2025-08-06T06:23:02.588511331Z" level=info msg="Initializing dissection cache..." subsys=monitor
      Ethernet        {Contents=[..14..] Payload=[..86..] SrcMAC=a2:cc:fe:3f:b5:99 DstMAC=0e:98:9e:22:60:65 EthernetType=IPv4 Length=0}
      IPv4    {Contents=[..20..] Payload=[..64..] Version=4 IHL=5 TOS=0 Length=84 Id=36008 Flags=DF FragOffset=0 TTL=63 Protocol=ICMPv4 Checksum=20958 SrcIP=172.20.2.179 DstIP=172.20.2.71 Options=[] Padding=[]}
      ICMPv4  {Contents=[..8..] Payload=[..56..] TypeCode=EchoRequest Checksum=65441 Id=54 Seq=1}
      CPU 01: MARK 0x0 FROM 1234 to-endpoint: 98 bytes (98 captured), state new, interface lxc6bfc4c764fad, , identity 47080->47080, orig-ip 172.20.2.179, to endpoint 1234
      ```

    - hubble 트래픽 관측 결과 : tracemessage = `to-endpoint`

      ```bash
      # curl-pod to netshoot-pod ping test
      $ hubble observe -f --protocol icmp
      ...
      Aug  6 06:50:26.228: default/curl-pod (ID:47080) -> default/netshoot-pod (ID:47080) to-endpoint FORWARDED (ICMPv4 EchoRequest)
      Aug  6 06:50:26.228: default/curl-pod (ID:47080) <- default/netshoot-pod (ID:47080) to-endpoint FORWARDED (ICMPv4 EchoReply)
      ```

    - `cilium/pgk/monitor/api/types.go` 파일의 `TraceObservationPoints` 변수를 확인하면 `TraceToLxc` 키를 사용할 경우 `to-endpoint` 메세지가 출력되는 것을 알 수 있다.

      ```go
      var TraceObservationPoints = map[uint8]string{
        TraceToLxc:       "to-endpoint",
        TraceToProxy:     "to-proxy",
        TraceToHost:      "to-host",
        TraceToStack:     "to-stack",
        TraceToOverlay:   "to-overlay",
        TraceToNetwork:   "to-network",
        TraceToCrypto:    "to-crypto",
        TraceFromLxc:     "from-endpoint",
        TraceFromProxy:   "from-proxy",
        TraceFromHost:    "from-host",
        TraceFromStack:   "from-stack",
        TraceFromOverlay: "from-overlay",
        TraceFromNetwork: "from-network",
        TraceFromCrypto:  "from-crypto",
      }
      ```

    - 다시 `bpf_lxc.c` 파일내부에서 `TRACE_TO_LXC` 유형으로 키워드를 검색하게 되면 `send_trace_notify6()`, `send_trace_notify4()` 함수에서 사용되고 있는 것을 알 수 있다.

    - IPv4를 사용하고 있기 때문에 `send_trace_notify4()` 함수의 코드가 포함된 `ipv4_policy()` 프로그램을 살펴보면 최종적으로 이 곳에서 패킷이 Pod에 전달되는 것을 확인할 수 있다.

      - proxy를 거치는 L7 트래픽인 경우 Envoy로 redirect 되도록 `POLICY_ACT_PROXY_REDIRECT` 값을 리턴하고

        ```c
        if (*proxy_port > 0)
          goto redirect_to_proxy;
        ...
        redirect_to_proxy:
        send_trace_notify4(ctx, TRACE_TO_PROXY, src_label, SECLABEL_IPV4, orig_sip,
              bpf_ntohs(*proxy_port), ifindex, trace.reason,
              trace.monitor);
        if (tuple_out)
          *tuple_out = *tuple;
        return POLICY_ACT_PROXY_REDIRECT;
        ```

      - 그렇지 않고, 바로 처리되는 경우 `send_trace_notify4()` 함수로 tracemessgae를 생성한 다음 `CTX_ACT_OK` 값을 리턴한다. 

        ```c
        send_trace_notify4(ctx, TRACE_TO_LXC, src_label, SECLABEL_IPV4, orig_sip, LXC_ID, ifindex, trace.reason, trace.monitor);

        return CTX_ACT_OK;
        ```

      - 리턴된 값은 `tail_ipv4_to_endpoint()` 함수에서 switch를 통해 envoy를 통해 처리되거나 직접 파드로 전달하도록 `redirect_ep()` 함수를 사용한다.

        ```c
        ret = ipv4_policy(ctx, ip4, src_label, &tuple, &ext_err, &proxy_port, from_tunnel);
        switch (ret) {
        case POLICY_ACT_PROXY_REDIRECT:
        ...
          ret = ctx_redirect_to_proxy4(ctx, &tuple, proxy_port, from_host);
          ctx_store_meta(ctx, CB_PROXY_MAGIC, ctx->mark);
          proxy_redirect = true;
          break;
        case CTX_ACT_OK:
        ...
          if (do_redirect)
            ret = redirect_ep(ctx, THIS_INTERFACE_IFINDEX, from_host, from_tunnel);
          break;
        default:
          break;
        ```
