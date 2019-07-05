# wechat-db-decrypt
获取 Windows 微信聊天记录数据库密码。

* 仅 python3；
* 获取密码时要求微信正在运行。

``` python
    # 打印所有联系人

    from pysqlcipher3 import dbapi2 as sqlite

    wechat_db_decrypt = WechatDatabaseDecrypt()
    wechat_db_decrypt.Init(0x1146340, 0x1131B64)  # 对应 2.6.6.25 版本

    db_filepath = os.path.join(wechat_db_decrypt.GetDatabaseFolder(), "MicroMsg.db")
    key = wechat_db_decrypt.CalculateKey(db_filepath)
    print('key=', key)

    micro_msg_conn = sqlite.connect(db_filepath)
    cur = micro_msg_conn.cursor()
    cur.execute('''PRAGMA key="x'%s'"''' % key)  # 这个也叫 key，那个也叫 key，好麻烦
    cur.execute("PRAGMA cipher_page_size=4096")
    print(cur.execute("select UserName, NickName from Contact").fetchall())
```

## 做法
### 用 OllyDbg 获取 raw_key（名称待定） 

根据这个帖子 https://bbs.pediy.com/thread-222652.htm 手动获取解密数据库的步骤如下：

1. 打开微信，先不要登陆；
2. OD 附加，切换到 WeChatWin.dll 模块，搜索字符串 "DBFactory::encryptDB"；
3. 往下有个 `test edx, edx`，下断，edx 就是了，长度 32。

微信是调用 sqlite3_key 进行解密，所以 key 可以传递包含字符 `\0` 字串，如果用 [DB Browser for SQLite](http://sqlitebrowser.org/) 或者 [pyslite3](https://github.com/rigglemania/pysqlcipher3) 打开时无法要做点处理，具体为什么要看 https://github.com/CovenantEyes/sqlcipher-windows/blob/6747108170c4f8db11d55119414434c13ce5eb80/StaticLib/src/crypto_impl.c#L848 。
之所以知道是这里，是通过编译 pyslite3 打日志打出来的。

``` python
    # 密码处理的逻辑
    def CalculateKey(self, db_filepath):
        """计算数据库密码"""
        salt = open(db_filepath, 'rb').read(16)
        derived_key = hashlib.pbkdf2_hmac('sha1', self.m_raw_key, salt, 64000, dklen=32)
        return binascii.hexlify(derived_key).decode()
```

### 用 CheatEngine 偏移搜索
大致步骤如下：

1. 启动微信，并登陆完成；
2. CheatEngine 启动并打开微信进程；
3. 用之前 OllyDbg 手动到的 raw_key（名称待定），得到地址；
4. 搜这个raw_key（名称待定）的地址，得到一个全局变量地址，查看详情可以看到相对于 WeChatWin.dll 的偏移；
5. 在 raw_key（名称待定）内存附近可以看到一个 wechat_id，搜索它的地址可以得到 wechat_id 的偏移。

### pysqlcipher3
手动编译可以利用
1. http://slproweb.com/products/Win32OpenSSL.html OpenSSL-Win32 要装 1.0.x；
2. 编译的时候利用这个 [sqlcipher-windows](https://github.com/CovenantEyes/sqlcipher-windows) 。

python3.6 32 位可以使用目录下的 egg 安装 `python -m easy_install pysqlcipher3-1.0.2-py3.6-win32.egg` 。

若遇到 ` ImportError: DLL load failed: 找不到指定的模块。`，可能是需要 OpenSSL 1.0.x 的 libeay32.dll。
> 试试下把OPENSSL的bin目录加到Path里，内部需要调用到libeay32.dll。如果没有安装OPENSSL，可以到这里下载对应版本 https://slproweb.com/products/Win32OpenSSL.html

感谢 [@cpiz](https://github.com/cpiz) 提供的解决方法。
