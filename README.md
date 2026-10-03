# Proxy Farm

Biến tài khoản VPN của bạn thành hàng chục cổng proxy **SOCKS5 + HTTP** độc lập, chạy
ngay trên máy bạn — mỗi cổng một quốc gia/thành phố với IP lối ra riêng, quản lý bằng
giao diện web.

![Proxy Farm](docs/screenshot.png)

- **Chạy local.** Không cần VPS, không mở cổng ra internet; UI và proxy mặc định chỉ
  nghe trên `127.0.0.1`.
- **Nhiều nhà cung cấp.** HMA (IKEv2 + chứng chỉ), WireGuard, OpenVPN, IKEv2 user/mật khẩu
  — trộn trong cùng một farm. NordVPN, Surfshark, PIA, Mullvad, IVPN, IPVanish, TorGuard,
  FastestVPN, Windscribe: nhập tài khoản **một lần**, farm tự tải danh sách máy chủ.
- **Tự phục hồi.** Mỗi cổng có kill-switch, watchdog và tự thử lại cho tới khi kết nối
  được; UI cho thấy từng bước đang làm.

## Mục lục

- [Tính năng](#tính-năng)
- [Nhà cung cấp hỗ trợ](#nhà-cung-cấp-hỗ-trợ)
- [Yêu cầu](#yêu-cầu)
- [Cài đặt nhanh](#cài-đặt-nhanh)
- [Sử dụng](#sử-dụng)
- [Cấu hình](#cấu-hình)
- [Cách hoạt động](#cách-hoạt-động)
- [Giới hạn đã biết](#giới-hạn-đã-biết)
- [Xử lý sự cố](#xử-lý-sự-cố)
- [Đóng góp](#đóng-góp)
- [Lưu ý pháp lý](#lưu-ý-pháp-lý)
- [Giấy phép](#giấy-phép)

## Tính năng

- Mỗi vị trí là một cổng phục vụ **cả SOCKS5 lẫn HTTP**, có user/mật khẩu sinh tự động
- **Kill-switch** trong từng cổng: tunnel chết thì proxy đóng, không bao giờ rò IP thật
- **Trạng thái trực tiếp**: *Chờ lượt → Đang bắt tay → Chờ dữ liệu → Online*, hoặc
  *Chờ thử lại* với đồng hồ đếm ngược, lý do thất bại, số lần thử và thời gian đã thử
- **Kiểm tra proxy ngay trên UI**: IP lối ra, nhà mạng, quốc gia có khớp không, độ trễ,
  thời gian TLS, tốc độ tải; kèm lệnh `curl` để chép
- Thao tác hàng loạt: bật / tắt / xoay IP / tự xoay theo lịch / xuất / xoá
- **Xuất danh sách** 4 định dạng: `host:port:user:pass`, `socks5://user:pass@host:port`,
  `host:port`, lệnh `curl`
- **Webhook xoay IP** cho hệ thống khác gọi
- Giới hạn số cổng theo từng nhà cung cấp (tuỳ chọn)
- Xem log từng cổng, dark/light, responsive (trên mobile bảng chuyển thành thẻ)
- CLI cho mọi thao tác

## Nhà cung cấp hỗ trợ

Ba cách nạp, từ dễ tới thủ công:

1. **Tự tải danh sách máy chủ** — chọn nhà cung cấp trong tab *Nhà cung cấp phổ biến*, nhập
   tài khoản dịch vụ (hoặc private key WireGuard) một lần; farm tải danh sách máy chủ công
   khai của nhà cung cấp và tạo sẵn một vị trí cho mỗi thành phố.
2. **Từ một file mẫu** — Windscribe: đưa một file `.ovpn` bất kỳ, farm nhân ra mọi khu vực.
3. **Kéo thả file** — bất kỳ `.conf` (WireGuard) / `.ovpn` (OpenVPN) / `.zip` của nhà cung
   cấp nào, hoặc máy chủ riêng của bạn. Cách này luôn dùng được.

| Nhà cung cấp | OpenVPN | WireGuard | IKEv2 user/mật khẩu | Ghi chú |
|---|---|---|---|---|
| **HMA / SurfEasy** | — | — | IKEv2 + chứng chỉ, tự lấy từ app | **đã kết nối thật** |
| **NordVPN** | tự tải | tự tải | tự tải | tên/mật khẩu *service credentials* |
| **Surfshark** | tự tải | tự tải | kéo thả / form | tên/mật khẩu dịch vụ; WG: private key |
| **Private Internet Access** | tự tải | — ¹ | form | |
| **Mullvad** | — ² | tự tải | — | đưa một file `.conf` tải từ trang tài khoản |
| **IVPN** | tự tải | tự tải | — | |
| **IPVanish** | tự tải | — | form | |
| **TorGuard** | tự tải | kéo thả | — | |
| **FastestVPN** | tự tải | — | — | |
| **Windscribe** | từ file mẫu | kéo thả | — | |
| Proton VPN, CyberGhost, PureVPN, hide.me, AirVPN, PrivadoVPN, VyprVPN | kéo thả | kéo thả (nếu có) | form (nếu có) | API danh sách máy chủ cần đăng nhập hoặc không công khai |
| **ExpressVPN** | kéo thả file *Manual config* | — | — | Lightway: **không hỗ trợ** |
| **Hotspot Shield** | — | — | — | chỉ có Hydra/Catapult: **không hỗ trợ** |
| Máy chủ của bạn (VPS) | kéo thả | kéo thả | form | |

¹ WireGuard của PIA phải đăng ký khoá qua API có đăng nhập cho từng phiên — chưa hỗ trợ.
² Mullvad đã ngừng OpenVPN từ 15/01/2026.

**Trạng thái kiểm chứng — nói thẳng:**

- *Đã kết nối thật*: HMA (IKEv2 + chứng chỉ) và WireGuard từ file `.conf` (các bản trước).
- *Danh sách máy chủ đã kiểm tra*: mọi ô "tự tải" ở trên — endpoint trả về dữ liệu thật và
  farm tạo được cấu hình (03/10/2026).
- *Bắt tay đã kiểm tra, chưa có tài khoản thật*: OpenVPN của NordVPN, Surfshark, PIA, IVPN,
  FastestVPN, TorGuard và IKEv2 của NordVPN — chứng chỉ máy chủ xác minh OK, máy chủ trả
  về *sai tài khoản* đúng như mong đợi khi dùng tài khoản giả. Nghĩa là cấu hình đúng, nhưng
  **chưa ai thử bằng tài khoản thật tới lúc có dữ liệu chạy qua**. Nếu bạn thử được, hãy
  báo lại qua issue.

**Giao thức độc quyền không thể hỗ trợ**: ExpressVPN *Lightway*, Hotspot Shield
*Hydra/Catapult*, VyprVPN *Chameleon*, NordVPN *NordWhisper*… chỉ chạy trong app của chính
họ. Với các nhà cung cấp này, chỉ dùng được khi họ cho tải **file OpenVPN/WireGuard thủ
công** (ExpressVPN có; Hotspot Shield thì không).

Một file cấu hình = một vị trí = một cổng proxy. Nhà cung cấp tự tải danh sách thì mỗi
thành phố = một vị trí (gom vài máy chủ ít tải nhất làm dự phòng).

## Yêu cầu

- **Docker** với Docker Compose v2. Trên macOS/Windows dùng Docker Desktop — kernel
  LinuxKit của nó có sẵn IPsec/xfrm và WireGuard (đã kiểm chứng trên Apple Silicon).
- Một tài khoản VPN của chính bạn. Với HMA: app HMA đã đăng nhập trên cùng máy (macOS).

## Cài đặt nhanh

```bash
git clone <repo-url> proxy-farm && cd proxy-farm
./run.sh
```

Mở **http://127.0.0.1:8090**. Nếu app HMA có trên máy, chứng chỉ được nạp tự động; vào
**Thêm vị trí**, chọn nơi muốn chạy rồi bấm **Bật**.

`./run.sh` tạo thư mục dữ liệu (mặc định `~/proxy-farm`), ghi `.env`, build hai image và
chạy manager bằng Docker Compose. Lần sau có thể dùng Compose trực tiếp:

```bash
docker compose up -d                  # chạy / cập nhật manager
docker compose down                   # dừng manager (các cổng proxy vẫn chạy)
docker compose build node manager     # build lại image sau khi sửa code
```

## Sử dụng

### Nạp nhà cung cấp

`./run.sh` tự làm phần lớn việc:

- **HMA** — nếu app HMA có trên máy, script copy `tokenCoreSE.json` vào `$FARM/inbox` và
  manager tự cài chứng chỉ. Chạy lại `run.sh` là đồng bộ lại.
- **File cấu hình** — thả `.conf` / `.ovpn` / `.zip` (kèm `ca.crt`, `ta.key` nếu file
  `.ovpn` trỏ tới) vào `$FARM/inbox`, tự nạp trong vòng một phút.
- **Gợi ý** — thư mục `~/Downloads` được mount **chỉ-đọc**; UI liệt kê các `.conf`/`.ovpn`
  chưa nạp để bạn bấm *Nạp*, không bao giờ tự nạp.

Không tự động được thì mở **Nhà cung cấp** ở thanh bên trái:

| Nhà cung cấp | Làm gì |
|---|---|
| **HMA** | Kéo thả `tokenCoreSE.json` (macOS: `/Library/Application Support/HMA VPN/state/vpn/tokenCoreSE.json`), hoặc file `.p12` kèm mật khẩu. |
| **Nhà cung cấp phổ biến** | Chọn nhà cung cấp, xem hướng dẫn lấy tài khoản, nhập tên/mật khẩu dịch vụ (hoặc private key WireGuard) rồi bấm *Tải máy chủ & thêm*. |
| **WireGuard / OpenVPN** | Kéo thả `.conf` / `.ovpn` / `.zip`, chọn cùng lúc `ca.crt`/`ta.key` nếu có. Nhà cung cấp đoán từ máy chủ trong file (`uk765.nordvpn.com` → nordvpn), quốc gia/thành phố từ tên file. File cần `auth-user-pass` thì nhập tài khoản ở mục *Tài khoản OpenVPN* ngay bên dưới — mỗi nhà cung cấp một lần. |
| **IKEv2 user/mật khẩu** | Điền máy chủ + tài khoản. Mỗi máy chủ thành một vị trí. Máy chủ dùng chứng chỉ tự ký thì chọn thêm file CA của nhà cung cấp. |

#### Tài khoản OpenVPN

Phần lớn nhà cung cấp OpenVPN yêu cầu **tên/mật khẩu dịch vụ** (service credentials) —
thường **khác** email/mật khẩu đăng nhập web (NordVPN, Surfshark, Proton, TorGuard,
Windscribe, CyberGhost, ExpressVPN, PureVPN). Tab *Nhà cung cấp phổ biến* ghi rõ chỗ lấy
cho từng nhà. Farm lưu tài khoản ở `$FARM/secrets/auth/<nhà-cung-cấp>.txt` (quyền 600) và
mount chỉ-đọc vào cổng; file `.ovpn` không bị sửa. Sai tài khoản thì cổng hiện
*Chờ thử lại · sai tài khoản* thay vì thử mãi một IP khác.

File `.ovpn` được làm sạch trước khi chạy: bỏ route/DNS/script/tuỳ chọn Windows, bỏ tuỳ
chọn OpenVPN 2.6 đã xoá (`keysize`, `ncp-disable`…), đổi `ns-cert-type` thành
`remote-cert-tls`, thêm `data-ciphers` cho cấu hình chỉ có `cipher` cũ. Chứng chỉ inline
và file `ca`/`cert`/`key`/`tls-auth`/`tls-crypt` nằm cạnh đều dùng được.

#### IKEv2 user/mật khẩu

Dùng strongSwan (EAP-MSCHAPv2). Chứng chỉ máy chủ được kiểm tra bằng bộ CA hệ thống
(Mozilla); nếu nhà cung cấp tự ký CA (NordVPN, VyprVPN…) hãy chọn file CA đó trong form —
khi đó máy chủ **chỉ** được tin theo CA này. NordVPN qua *Nhà cung cấp phổ biến* tự tải
CA.

### Dùng proxy

```bash
curl -x socks5h://USER:PASS@127.0.0.1:29001 https://ipinfo.io
curl -x http://USER:PASS@127.0.0.1:29001   https://ipinfo.io
```

Trong app khác: loại **SOCKS5** (hoặc HTTP), host `127.0.0.1`, port theo cột *Điểm cuối*,
user/mật khẩu hiện ở đầu trang.

### Bật, tắt và trạng thái

- **Bật** một cổng: tạo container mới từ image mới nhất. **Tắt**: đóng phiên VPN, xoá
  container, giữ lại số cổng. Thanh lọc *Đang bật / Đã tắt / Tất cả* tách hai nhóm.
- Cổng đang bật mà chưa lên thì **tự thử cho tới khi kết nối được**, không bao giờ tự bỏ.
  Rê chuột vào cột trạng thái để xem nó đang làm gì và vì sao lần trước thất bại.
- Nút ⚡ (hoặc chọn nhiều dòng → *Kiểm tra*, tối đa 20) chạy thử thật qua cổng đó.

### Giới hạn số cổng

Mặc định HMA **không giới hạn** (đã chạy 27+ cổng cùng lúc). Với nhà cung cấp chỉ cho một
số kết nối cùng lúc, bật công tắc *Giới hạn* trong thẻ nhà cung cấp và nhập số tối đa;
farm sẽ từ chối bật quá số đó. Giá trị gợi ý: ProtonVPN/NordVPN 10, ExpressVPN 8,
CyberGhost 7, Mullvad 5.

### Webhook xoay IP

```
GET http://127.0.0.1:8090/api/rotate?key=<rotate_key>&port=29001
GET http://127.0.0.1:8090/api/rotate?key=<rotate_key>&all=1
```

`rotate_key` xem và đổi trong **Cài đặt**.

### CLI

```bash
docker exec pf-manager python3 farm.py up US JP DE-16-BERLIN   # mã nước / key / all
docker exec pf-manager python3 farm.py ls
docker exec pf-manager python3 farm.py rotate US-NY-NEW-YORK
docker exec pf-manager python3 farm.py stop|start|down <KEY..>
docker exec pf-manager python3 farm.py autorotate <KEY..> 30
docker exec pf-manager python3 farm.py logs <KEY>

# nhà cung cấp
docker exec pf-manager python3 farm.py presets                    # danh sách + cách nạp
docker exec -it pf-manager python3 farm.py import nordvpn          # hỏi tên/mật khẩu dịch vụ
docker exec -it pf-manager python3 farm.py import nordvpn ikev2
docker exec -it pf-manager python3 farm.py import mullvad wireguard
docker exec -it pf-manager python3 farm.py import surfshark openvpn 2   # 2 máy chủ/thành phố
docker exec -it pf-manager python3 farm.py auth cyberghost myuser  # tài khoản cho file .ovpn
docker exec pf-manager python3 farm.py add /inbox/*.ovpn /inbox/ca.crt
```

`import` đọc tài khoản từ biến môi trường nếu có (`PF_USER`, `PF_PASS`, `PF_WG_KEY`,
`PF_WG_ADDRESS`, `PF_TEMPLATE`), không thì hỏi trên terminal.

## Cấu hình

Biến cho `./run.sh` (được ghi vào `.env`, lần sau không cần nhắc lại):

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `FARM` | `~/proxy-farm` | Thư mục dữ liệu: chứng chỉ, cấu hình, trạng thái. Không nằm trong repo. |
| `PORT` | `8090` | Cổng UI, chỉ trên `127.0.0.1`. |
| `BIND` | `127.0.0.1` | Địa chỉ các cổng proxy lắng nghe. Đặt IP LAN/Tailscale nếu máy khác cần dùng. |
| `SCAN` | `~/Downloads` | Thư mục quét gợi ý file cấu hình (chỉ-đọc). Để trống là tắt. |

Trong UI (**Cài đặt**): user/mật khẩu proxy, địa chỉ lắng nghe, cổng bắt đầu, MTU, DNS
trong tunnel, ngưỡng watchdog, khoá webhook. Thay đổi nằm trong `docker run` của từng
cổng chỉ có hiệu lực sau khi dựng lại — nút *Lưu & dựng lại* làm việc đó.

## Cách hoạt động

```
                    Docker trên máy bạn
  ┌──────────────────────────────────────────────────────────────┐
  │  pf-manager   ── UI :8090 ──  điều khiển qua docker.sock      │
  │      │ docker run                                             │
  │      ▼                                                        │
  │  pf-<vị-trí>    (1 container / cổng)                         │
  │    drivers/<protocol>.sh ══► máy chủ VPN của nhà cung cấp     │
  │    gost SOCKS5+HTTP trên :1080 → publish 127.0.0.1:290NN      │
  │    kill-switch · DoH · watchdog tự phục hồi                   │
  └──────────────────────────────────────────────────────────────┘
      127.0.0.1:29001 → US New York
      127.0.0.1:29002 → JP Tokyo   ...
```

Mỗi cổng là một container riêng vì mỗi tunnel cần network namespace, bảng định tuyến và
kill-switch riêng. Các container nằm chung nhóm `proxy-farm` trong Docker Desktop.

Trong mỗi container:

- **kill-switch** — bỏ default route; chỉ gói của chính tunnel và dải private đi mạng
  thật. Tunnel chết ⇒ proxy fail closed.
- **DoH** — gost phân giải tên miền qua `https://1.1.1.1/dns-query`, vì vài máy chủ chặn
  UDP 53.
- **watchdog** — mỗi 15 giây tải thật qua chính proxy; lỗi 3 lần liên tiếp ⇒ đóng phiên,
  thoát, Docker khởi động lại và kết nối lại.
- **cổng nguồn ngẫu nhiên** — mỗi lần kết nối, cổng IKE 500/4500 được đổi sang một cặp
  cổng mới, để không bao giờ dính lại một luồng mạng đã hỏng.

`node/entrypoint.sh` lo phần dùng chung; phần riêng của từng giao thức nằm trong
`node/drivers/<protocol>.sh`. Xem [Đóng góp](#đóng-góp) để thêm giao thức.

### Vì sao HMA dùng được dù app không cho tải file cấu hình

HMA chạy trên hạ tầng **SurfEasy / Gen Digital**. App xác thực bằng **chứng chỉ client
(PKCS#12)** qua IKEv2 tới `*.ult.surfeasy.mobi` (74 nước / 115 thành phố). Farm lấy chứng
chỉ đó từ app rồi kết nối IKEv2 bằng **libreswan** — đúng giao thức app dùng. Hai điểm
không hiển nhiên:

1. Máy chủ trả về IDr (`ipsec.surfeasy.mobi`) **không khớp SAN** trong chính chứng chỉ của
   nó. strongSwan từ chối; libreswan với `require-id-on-certificate=no` chấp nhận (giống
   client IKEv2 của Apple).
2. Phải **đặt MTU** (`mtu=1400`). Thiếu nó thì bắt tay TCP vẫn xong nhưng gói lớn đầu
   tiên (TLS ClientHello) bị rớt âm thầm và mọi kết nối treo.

<details>
<summary>Trích chứng chỉ bằng tay (UI đã làm hộ)</summary>

`tokenCoreSE.json` chứa `DeviceManager.device` (base64 của JSON); trong đó
`credentials.certificate` là PKCS#12 dạng base64 và `credentials.certificatePassword` là
mật khẩu của nó.

```bash
openssl pkcs12 -in client.p12 -passin pass:<pass> -nokeys -clcerts -out client.pem
openssl pkcs12 -in client.p12 -passin pass:<pass> -nocerts -nodes  -out client.key
openssl pkcs12 -in client.p12 -passin pass:<pass> -nokeys -cacerts -out ca-int.pem
```

Thêm `-legacy` nếu OpenSSL 3 báo lỗi thuật toán cũ. Hai CA trung gian công khai mà máy chủ
không gửi kèm đã nằm sẵn trong image (`node/ca/`).
</details>

## Giới hạn đã biết

- **Bắt tay xong nhưng không có dữ liệu** — hành vi của chính HMA (app chính chủ cũng báo
  *Connected* mà không nhận về gói nào). Node phát hiện sau ~20 giây, đóng phiên và thử
  lại; lần sau thường chạy được. Bật 27 cổng cùng lúc: ~15 lên ngay, 25/27 sau ~7 phút.
- **Một số cụm máy chủ điều phối của HMA rớt gói** (đo được ở cụm Frankfurt: 30–60% lần
  thử được trả lời). Node tự thử lại.
- **HMA cắt mỗi phiên sau ~4,5 giờ.** Node nối lại sau vài giây; IP lối ra có thể đổi.
- **Máy ngủ thì mọi tunnel chết.** Để chạy liên tục, cắm sạc và đặt máy không ngủ khi
  cắm sạc; gập máy vẫn ngủ.
- **Đừng bật app HMA trên máy đang chạy farm** — app đưa toàn bộ mạng của máy vào VPN và
  các tunnel của farm rớt theo.
- Không chạy farm trên hai máy cùng lúc với cùng một chứng chỉ.
- Driver `openvpn` và `ikev2-eap` đã được thử bắt tay thật với máy chủ của nhiều nhà cung
  cấp (tới bước máy chủ từ chối tài khoản giả), nhưng **chưa được thử bằng tài khoản thật**.
- Danh sách máy chủ lấy từ endpoint công khai của nhà cung cấp; họ có thể đổi hoặc đóng
  endpoint bất cứ lúc nào. Khi đó cách kéo thả file vẫn dùng được.
- Proton VPN, CyberGhost, ExpressVPN, PureVPN, VyprVPN, hide.me, AirVPN không có danh sách
  máy chủ công khai không cần đăng nhập (hoặc farm không kiểm tra được) — phải tải file
  cấu hình thủ công.
- Không hỗ trợ giao thức độc quyền (Lightway, Hydra/Catapult, Chameleon, NordWhisper) và
  các máy chủ đặc biệt (obfuscated, double VPN, Onion, IP riêng).
- Giới hạn số kết nối cùng lúc là số nhà cung cấp công bố; farm tự điền sẵn, đổi được trong
  thẻ nhà cung cấp.

## Xử lý sự cố

| Triệu chứng | Làm gì |
|---|---|
| Cổng *Chờ thử lại · không có dữ liệu* | Lỗi phía nhà cung cấp; cứ để farm tự thử, hoặc bấm *Đổi IP* để thử ngay. |
| Cổng *Chờ thử lại · không trả lời* | Máy chủ điều phối không trả lời; farm tự thử lại và đổi sang IP khác của vị trí. |
| Cổng *Chờ thử lại · sai tài khoản* | Máy chủ từ chối tên/mật khẩu. Dùng tài khoản **dịch vụ** (không phải email đăng nhập), nhập lại ở *Nhà cung cấp → Tài khoản OpenVPN* hoặc chạy lại `import`. |
| Cổng *Chờ thử lại · lỗi chứng chỉ* | IKEv2: thiếu CA của nhà cung cấp hoặc sai *ID máy chủ*; chọn file CA trong form IKEv2. |
| OpenVPN không bao giờ lên, log có `TLS key negotiation failed` | Mạng chặn cổng UDP đó; dùng file `.ovpn` TCP (hoặc cổng 443) của nhà cung cấp. |
| Tất cả cổng rớt cùng lúc | Máy vừa ngủ hoặc Docker vừa khởi động lại; các cổng tự lên lại trong vài phút. |
| Docker Desktop báo `Internal Server Error` | Máy ảo Docker bị treo: thoát và mở lại Docker Desktop. |
| Xem chi tiết một cổng | Nút log trên dòng đó, hoặc `docker logs pf-<vị-trí>`. |

## Đóng góp

Pull request và issue đều được chào đón.

**Thêm một giao thức** = thêm file `node/drivers/<protocol>.sh` định nghĩa các hàm:

| Hàm | Bắt buộc | Việc |
|---|---|---|
| `driver_resolve` | có | In ra các IP điểm cuối (mỗi dòng một IP) để ghim route |
| `driver_up` | có | Dựng tunnel |
| `driver_outer` | không | Thêm `ip rule` cho gói của chính tunnel |
| `driver_established` | không | Trả về 0 khi tunnel đã dựng (để UI hiện *Chờ dữ liệu*) |
| `driver_stuck` | không | Trả về 0 khi chắc chắn lần thử này hỏng, để bỏ sớm |
| `driver_down` | không | Đóng phiên sạch sẽ khi dừng |

Rồi thêm nhận dạng file cấu hình trong `manager/providers.py` (`detect_protocol`) nếu cần.

**Thêm một nhà cung cấp** = thêm một mục vào `manager/presets.json` (tên miền máy chủ, số
kết nối tối đa, chỗ lấy tài khoản, giao thức nào nạp thế nào). Nếu họ có danh sách máy chủ
**công khai, không cần đăng nhập**, viết importer trong `manager/providers.py` và test trong
`tests/`. Chỉ đánh dấu `list_checked` khi đã thấy endpoint trả dữ liệu thật, và
`connect_verified` khi đã kết nối được bằng tài khoản thật.

Trước khi gửi PR:

```bash
sh -n node/entrypoint.sh node/drivers/*.sh
python3 -m py_compile manager/farm.py manager/providers.py
python3 -m unittest discover -s tests -v
sh tests/test_openvpn_sanitize.sh
```

rồi thử thật bằng `./run.sh`. GitHub Actions (`.github/workflows/ci.yml`) chạy các bước
này và build hai image.
**Không bao giờ commit** chứng chỉ, file cấu hình VPN, `.env` hay thư mục dữ liệu.

## Lưu ý pháp lý

Công cụ này dùng **tài khoản VPN của chính bạn** trên **máy của chính bạn**. Nhà cung cấp
VPN thường **cấm chia sẻ hoặc bán lại** kết nối — đừng mở proxy ra internet hay chia cho
người khác. Bạn tự chịu trách nhiệm tuân thủ điều khoản dịch vụ của nhà cung cấp và luật
pháp nơi bạn sống. Dự án không liên quan tới HMA, SurfEasy, Gen Digital hay bất kỳ nhà cung
cấp VPN nào.

## Giấy phép

[MIT](LICENSE). Các thành phần đi kèm trong image (libreswan, strongSwan, gost, WireGuard
tools, OpenVPN) theo giấy phép riêng của chúng. Tên các nhà cung cấp VPN là thương hiệu của
chủ sở hữu tương ứng.
