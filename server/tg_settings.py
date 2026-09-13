"""Telegram 推送配置；使用系统 curl 的 TLS 和 SOCKS5 实现。"""
import json
import os
import re
import tempfile
import threading
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT = dict(enabled=False, bot_token='', chat_id='', proxy_url='', proxy_username='', proxy_password='')
LOCK = threading.RLock()

class Settings:
    def __init__(self, path):
        self.path = Path(path)

    def load(self):
        with LOCK:
            if not self.path.exists():
                return DEFAULT.copy()
            try:
                data = json.loads(self.path.read_text())
                if not isinstance(data, dict):
                    raise ValueError()
                return {**DEFAULT, **data}
            except Exception:
                raise ValueError('推送配置读取失败，请检查配置文件') from None

    def public(self):
        c = self.load()
        return {k: c[k] for k in ('enabled', 'chat_id', 'proxy_url', 'proxy_username')} | {
            'token_configured': bool(c['bot_token']), 'proxy_password_configured': bool(c['proxy_password'])}

    def save(self, data):
        with LOCK:
            if not isinstance(data, dict) or set(data) - set(DEFAULT) - {'clear_token', 'clear_proxy_password'}:
                raise ValueError('配置字段不正确')
            c = self.load()
            for k, value in data.items():
                if k in ('clear_token', 'clear_proxy_password'):
                    if not isinstance(value, bool):
                        raise ValueError('清除选项必须为布尔值')
                    continue
                if k == 'enabled':
                    if not isinstance(value, bool):
                        raise ValueError('推送开关必须为布尔值')
                elif not isinstance(value, str) or len(value) > 512 or any(ord(x) < 32 for x in value):
                    raise ValueError('配置字段类型、长度或字符不正确')
                if k in ('bot_token', 'proxy_password') and value == '':
                    continue
                c[k] = value.strip() if k != 'proxy_password' and isinstance(value, str) else value
            if data.get('clear_token'): c['bot_token'] = ''
            if data.get('clear_proxy_password'): c['proxy_password'] = ''
            if c['bot_token'] and not re.fullmatch(r'[0-9]{5,20}:[A-Za-z0-9_-]{25,100}', c['bot_token']):
                raise ValueError('机器人令牌格式不正确')
            if c['chat_id'] and not re.fullmatch(r'-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31}', c['chat_id']):
                raise ValueError('接收聊天 ID 格式不正确')
            if c['proxy_url']:
                try:
                    u = urlsplit(c['proxy_url'])
                    if u.scheme not in ('http','https','socks5','socks5h') or not u.hostname or not u.port or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:
                        raise ValueError()
                except Exception:
                    raise ValueError('代理须为 http/https/socks5/socks5h://地址:端口；认证请填独立字段') from None
            if ':' in c['proxy_username']:
                raise ValueError('代理用户名不能包含冒号')
            if c['enabled'] and (not c['bot_token'] or not c['chat_id']):
                raise ValueError('启用推送前请填写令牌和聊天 ID')
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix='.telegram-', dir=self.path.parent)
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(c, f, ensure_ascii=False)
                    f.flush(); os.fsync(f.fileno())
                os.replace(name, self.path)
            finally:
                if os.path.exists(name): os.unlink(name)
            return self.public()

    def send(self, text):
        c = self.load()
        if not c['bot_token'] or not c['chat_id']:
            return {'ok': False, 'msg': '请先保存机器人令牌及接收聊天 ID'}
        # 所有敏感数据经标准输入送入 curl，不进入命令行参数或日志。
        quote = lambda s: '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r') + '"'
        payload = json.dumps({'chat_id': c['chat_id'], 'text': str(text)[:3500], 'disable_web_page_preview': True}, ensure_ascii=False)
        lines = ['url = ' + quote('https://api.telegram.org/bot' + c['bot_token'] + '/sendMessage'),
                 'proxy = ' + quote(c['proxy_url']), 'noproxy = ""', 'silent',
                 'connect-timeout = 8', 'max-time = 20', 'max-filesize = 1048576',
                 'proto = "=https"', 'header = "Content-Type: application/json"', 'data = ' + quote(payload)]
        if c['proxy_username'] or c['proxy_password']:
            lines.append('proxy-user = ' + quote(c['proxy_username'] + ':' + c['proxy_password']))
        env = {k:v for k,v in os.environ.items() if k.lower() not in ('http_proxy','https_proxy','all_proxy','no_proxy')}
        try:
            r = subprocess.run(['curl', '-q', '--config', '-'], input='\n'.join(lines)+'\n', capture_output=True, text=True, timeout=24, env=env)
            if r.returncode:
                return {'ok': False, 'msg': '连接失败，请检查代理、网络或证书设置'}
            d = json.loads(r.stdout)
            m = d.get('result', {})
            if d.get('ok') is True and isinstance(m.get('message_id'), int) and isinstance(m.get('chat'), dict):
                chat = m['chat']
                matches = str(chat.get('id')) == c['chat_id'] or (c['chat_id'].startswith('@') and str(chat.get('username', '')).lower() == c['chat_id'][1:].lower())
                if matches:
                    return {'ok': True, 'msg': '测试消息已获 Telegram 确认', 'message_id': m['message_id'], 'chat_id': chat.get('id')}
            code = d.get('error_code')
            msg = {401: '机器人令牌无效', 403: '机器人无法发送，请先打开机器人并点击开始', 400: '接收聊天不存在或参数错误', 429: '请求过于频繁，请稍后再试'}.get(code, 'Telegram 未确认发送成功')
            return {'ok': False, 'msg': msg}
        except Exception:
            return {'ok': False, 'msg': '推送失败，请检查配置与网络；敏感信息已隐藏'}

    def notify(self, sender, content):
        if not self.load()['enabled']:
            return {'ok': False, 'msg': '自动推送未启用'}
        return self.send('收到新短信\n发送号码：' + str(sender) + '\n\n' + str(content))
