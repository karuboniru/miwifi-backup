# miwifi-backup

将小米路由器的配置备份解密为可编辑的 JSON，也可以把 JSON 重新加密为原格式的 `.tar.gz`。工具离线运行，仅使用 Python 3.10+ 标准库。已验证的机型为 Xiaomi 路由器 BE6500（RN02），固件版本为 1.0.64。

## 使用

```sh
python3 miwifi_backup.py decrypt backup.tar.gz config.json
python3 miwifi_backup.py encrypt config.json repacked.tar.gz
```

按提示输入路由器的序列号和 LAN MAC。序列号只需前五个字符，LAN MAC 可以带冒号。路由器首页有时显示 WAN MAC，请核对局域网接口的地址。非交互调用可通过 `--sn` 和 `--lan-mac` 传值。

JSON 中的 `description` 保存备份项目列表，`config` 保存配置。明文可能含有 Wi-Fi 和拨号密码。工具以私有权限创建新文件，目标路径已存在时会退出。

## 格式与测试

归档包含项目列表 `cfg_backup.des` 和加密的配置 `cfg_backup.mbu`。RN02 的 CBC 实现使用修改过的 AES-128 密钥扩展：RotWord 的末字节为零，第八轮常量也为零。测试使用合成数据和固定的固件兼容性向量。

```sh
python3 -m unittest discover -v
```
