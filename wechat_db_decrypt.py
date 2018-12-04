from win32api import(
    OpenProcess,
    CloseHandle
)
from win32process import(
    EnumProcesses,
    EnumProcessModules,
    GetModuleFileNameEx, 
)
from winreg import (
    OpenKey,
    QueryValueEx,
    HKEY_CURRENT_USER,
)
import win32com.client as win32com
import ctypes
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
from win32con import PROCESS_ALL_ACCESS

import os
import hashlib
import binascii


class WechatDatabaseDecryptException(Exception):
    pass

class WechatDatabaseDecrypt:
    def Init(self, offset_wechat_id, offset_db_key_pointer,
            process_name='wechat.exe'):  # 似乎有其他进程名的需求
        """GetPassword 前需要调用，失败抛出 WechatDatabaseDecryptException
        offset_wechat_id: 存放 wechat id 得指针的地址相对于 wechatwin.dll 的偏移
        offset_db_key_pointer: 存放数据库密码的指针的地址相对于 wechatwin.dll 的偏移
        偏移依赖于特定微信版本
        """
        pid = self._GetPidFromProcessName(process_name)
        if not pid:
            raise WechatDatabaseDecryptException("进程 {process_name} 不存在".format(process_name))

        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            raise WechatDatabaseDecryptException("打开进程 {pid} 失败".format(pid))

        module_name = 'wechatwin.dll'
        module_address = self._FindProcessModuleAddress(process_handle, module_name)
        if not module_address:
            CloseHandle(process_handle)
            raise WechatDatabaseDecryptException("模块 {module_name} 不存在".format(module_name))

        wechat_id = self._ReadWechatId(process_handle, module_address + offset_wechat_id)
        if not wechat_id:
            CloseHandle(process_handle)
            raise WechatDatabaseDecryptException("读取 wechat id 失败")

        raw_key = self._ReadDatabaseRawKey(process_handle, module_address + offset_db_key_pointer)
        if not raw_key:
            CloseHandle(process_handle)
            raise WechatDatabaseDecryptException("读取 key 失败")

        CloseHandle(process_handle)
        self.m_raw_key = raw_key
        self.m_wechat_id = wechat_id
        self.m_db_folder = self._FindDatabaseFolder(wechat_id)

    def GetDatabaseFolder(self):
        return self.m_db_folder

    def CalculateKey(self, db_filepath):
        """计算数据库密码"""
        salt = open(db_filepath, 'rb').read(16)
        derived_key = hashlib.pbkdf2_hmac('sha1', self.m_raw_key, salt, 64000, dklen=32)
        return binascii.hexlify(derived_key).decode()

    def _GetPidFromProcessName(self, process_name):
        """取进程 id，失败返回 None"""
        wmi = win32com.GetObject('winmgmts:')
        pid_list = wmi.ExecQuery("SELECT * FROM Win32_Process where name = '{process_name}'".format(
            process_name=process_name.replace("'", "")))
        if len(pid_list):
            return int(pid_list[0].handle)

    def _FindProcessModuleAddress(self, process_handle, module_name):
        """取进程模块地址（句柄），失败返回 None"""
        module_address = None
        for module_handle in EnumProcessModules(process_handle):
            the_name = os.path.basename(GetModuleFileNameEx(process_handle, module_handle)).lower()

            if the_name == module_name:
                module_address = module_handle  # 模块句柄实际上就是模块地址
                break
        return module_address

    def _ReadWechatId(self, process_handle, address):
        """读取 wechat id，用于自动取数据库路径，失败返回 None"""
        raw_process_handle = process_handle.handle
        wechat_id_address = ctypes.c_int32()
        if not ReadProcessMemory(raw_process_handle, address, ctypes.byref(wechat_id_address), 4, None):
            return None

        wechat_id_length = 64
        wechat_id = ctypes.create_string_buffer(wechat_id_length)
        ReadProcessMemory(raw_process_handle, wechat_id_address, ctypes.byref(wechat_id), wechat_id_length, None)
        return wechat_id.value.decode()

    def _ReadDatabaseRawKey(self, process_handle, address):
        """从内存中读取数据库 key，key 需要经过 CalculateKey 处理后 sqlcipher 才能使用"""
        raw_process_handle = process_handle.handle
        key_address = ctypes.c_int32()
        if not ReadProcessMemory(raw_process_handle, address, ctypes.byref(key_address), 4, None):
            return None

        key_length = 32
        key = ctypes.create_string_buffer(key_length)
        ReadProcessMemory(raw_process_handle, key_address, ctypes.byref(key), key_length, None)
        if not key.value:
            return None

        return key.raw

    def _FindMyDocPath(self):
        """取得“我的文档”的路径"""
        key_handle = OpenKey(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
        path, _ = QueryValueEx(key_handle, 'Personal')
        CloseHandle(key_handle)
        return path

    def _FindDatabaseFolder(self, wechat_id):
        """取默认数据库存放路径"""
        key_handle = OpenKey(HKEY_CURRENT_USER, r"Software\Tencent\WeChat")
        folder, _ = QueryValueEx(key_handle, 'FileSavePath')
        CloseHandle(key_handle)
        if folder == 'MyDocument:':
            folder = self._FindMyDocPath()
        return os.path.join(folder, 'WeChat Files', wechat_id, 'Msg')


if __name__ == '__main__':
    from pysqlcipher3 import dbapi2 as sqlite

    wechat_db_decrypt = WechatDatabaseDecrypt()
    wechat_db_decrypt.Init(0x1146340, 0x1131B64)  # 对应 2.6.6.25 版本

    db_filepath = os.path.join(wechat_db_decrypt.GetDatabaseFolder(), "MicroMsg.db")
    key = wechat_db_decrypt.CalculateKey(db_filepath)
    print('key=', key)

    micro_msg_conn = sqlite.connect(db_filepath)
    cur = micro_msg_conn.cursor()
    cur.execute('''PRAGMA key="x'%s'"''' % key)  # 为了配合这里才叫 key，本来叫 password 多好
    cur.execute("PRAGMA cipher_page_size=4096")
    print(cur.execute("select UserName, NickName from Contact").fetchall())