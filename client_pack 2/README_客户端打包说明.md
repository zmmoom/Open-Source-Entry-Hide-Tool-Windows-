# HideAppleAccount 客户端 · 打包说明

## 授权方式
配合**授权管理网站**使用，软件内不输入任何序列号：
- 打开软件直接进主界面
- 点 **Start**：已注册设备直接运行
- 未注册 → 弹窗只显示一句“设备未注册，请联系管理员，在授权网站完成注册后，再回到软件点击该按钮”，点“好的”
- 代理/客户在网站登录后输入该 UDID 注册，回来再点 Start 即可

## 文件清单
```
app.py                        # 主程序（覆盖旧 app.py）
index.html                    # 界面（覆盖旧 index.html）
license_client.py             # 授权校验模块
atc_native_bridge.py          # 原生 ATC 桥（覆盖）
airlift_attack.py             # 攻击链（finish 原码；如项目已是真机成功版可不必覆盖）
webview2_bootstrap.py         # WebView2 兜底（静默，不弹窗）
collect_apple_dll.py          # 【可选】收集苹果 DLL，做免装 iTunes 版
app.ico                       # 程序图标
HideAppleAccount-OneFile.spec # 单文件打包配置
```
> 没有启动屏：双击直接进主界面（避免部分机器出现空白 Tk 窗口）。
> 每次打包务必先清缓存：`rmdir /s /q build & rmdir /s /q dist`。
> 攻击链核心（hide/、driver_libs/、usbmux_helper.py、libimobiledevice_wrapper.py 等）保持原样，不要动。

## 推荐：内置苹果 DLL（客户免装 iTunes，握手更稳）
在**你自己真机跑成功的那台电脑**上操作（用的就是验证过能成功的那套 DLL）：

1. 先装好驱动（爱思 / iTunes 均可），确认手机能识别。
2. 项目根目录执行：
```
python collect_apple_dll.py
```
脚本会自动递归解析依赖，把 `AirTrafficHost.dll`、`CoreFoundation.dll` 及全部非系统依赖复制到 `apple_dll\` 文件夹。
3. 看打印结果确认 `AirTrafficHost.dll`、`CoreFoundation.dll` 都在列表里。
4. 直接正常打包即可——`apple_dll` 文件夹存在时，spec 会自动把它打进 exe，软件运行时优先用内置 DLL，不再依赖客户电脑装没装、版本对不对。

> 必须是 64 位 Python / 64 位 DLL（脚本和桥都会校验位数）。
> 不做这一步也能用，但客户电脑需自备正确版本的苹果驱动（容易卡 ReadyForSync）。

## 打包
确认已安装 PyInstaller：
```
pip install pyinstaller
```
清缓存并打包：
```
rmdir /s /q build & rmdir /s /q dist & pyinstaller HideAppleAccount-OneFile.spec
```
产物：
```
dist\HideAppleAccount.exe
```
单个 exe，使用系统 WebView2；内置苹果 DLL 后预计 60~80MB。

## 真机验证
1. 未注册点 Start → 只弹一句话 + “好的”
2. 网站登录 → 注册该 UDID
3. 回软件再点 Start → 直接跑通
4. 跑完**重启手机**，进设置确认 iCloud 账号已消失
5. 断网 / 未注册 / 停用账号 → 应被拒绝

## 客户使用要点（避免卡 90 多 / ReadyForSync）
- 若用的是【未内置 DLL】版：先装 iTunes 64 位（官网 .exe 版）或同版本爱思
- 完全退出爱思/iTunes 再开软件（它们会占用 USB 通道）
- 插主机背后 USB 口，不用 Hub/延长线
- 手机解锁、亮屏停在主屏，点“信任此电脑”
