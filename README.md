# iOS Location Spoofer

[English](README.en.md) · **中文**

用代理软件的 HTTPS 解密功能，把 Apple 地图定位骗到世界任何角落。

> 📖 **新手直接看这篇** → [**小白保姆级图文教程**](使用教程.md)（一步步教你安装、配置、生效，含常见问题排查）

## 参考项目

本项目基于 [acheong08/ios-location-spoofer](https://github.com/acheong08/ios-location-spoofer) 的核心研究。原始项目是用 Go 写的独立 iOS App，通过自建 VPN + MITM 代理实现定位欺骗。

本仓库将其核心逻辑移植为 JavaScript，适配到 Shadowrocket / Surge / Loon / Quantumult X / Stash 五个代理平台，免编译、免开发者账号，即导即用。

### 相比原版新增的功能

- **多平台支持** — 从单一 iOS App 扩展到五个代理软件，覆盖更多用户
- **蜂窝基站坐标修改** — 原版 Go 只改了 WiFi 热点坐标，JS 版额外处理了 CellTower（字段 22/24）的坐标替换
- **多响应格式兼容** — 自动检测 Apple 回应的封装格式（ARPC / synthetic / marker / bare），确保改后还能被 iOS 正确识别
- **运动状态伪造** — 一并改写 motionActivityType 和 motionActivityConfidence，减少被系统识破的可能

## 怎么回事

iPhone 看 Wi-Fi 信号和基站信号，拿着 BSSID 列表去问 Apple 这些设备在什么位置。Apple 回一份坐标清单，iOS 根据这些坐标算出自己在哪里。

这套配置做的事情很简单：**在 Apple 发回坐标的路上拦截下来，全部改成你想要的数字**。iPhone 拿到改造过的坐标，算出来就是你指定的地方。

## 支持哪些软件

| 软件 | 文件 | 导入方法 | 状态 |
|------|------|---------|------|
| Shadowrocket（小火箭） | `ios-location-spoofer.sgmodule` | 配置 → 右上角 + | ✅ 实测通过 |
| Surge | `ios-location-spoofer-surge.sgmodule` | 首页 → 模块 → 安装新模块 | ✅ 实测通过 |
| Loon | `ios-location-spoofer.lnplugin` | 设置 → 插件 → 添加插件 | ✅ 实测通过 |
| Quantumult X | `ios-location-spoofer.snippet` | 设置 → 重写 → 添加 | 🟡 待测试 |
| Stash | `ios-location-spoofer.stoverride` | 覆写 → 安装覆写 | ✅ 实测通过 |

> 欢迎测过的佬友在 Issue 区报实测结果；不通的地方欢迎直接提 PR 改 —— 至少写明**哪个软件、哪个版本、什么系统、报错的日志原文**。

## 怎么用

1. 软件里打开 HTTPS 解密 / MITM 开关
2. 安装并信任 CA 证书（设置 → 通用 → VPN 与设备管理 → 安装 → 证书信任设置 → 启用）
3. 导入模块文件，勾上启用
4. 断开重连 VPN，开关定位服务
5. 打开地图 App 验证

### Loon 额外说明

1. 导入 `ios-location-spoofer.lnplugin` 后，在 **设置 → 插件** 里打开插件配置页
2. 可直接填 **纬度 / 经度**；**地址搜索** 由每 15 分钟的定时任务联网解析并缓存（首次请直接填经纬度，或保存地址后等一轮 cron）
3. 必须开启 Loon 的 **MITM** 并信任证书，且插件内 `[mitm]` 四个域名生效
4. 插件含 **Prepare** 请求脚本（设置 `Accept-Encoding: identity`，避免 gzip 引发 `zip decompress error` / 脚本超时）
5. 改坐标后关开定位；调试打开 **调试日志**，在 Loon 日志搜 `Location spoofer`

> 日志若出现 `Evaluate script timeout` 或 `zip decompress error:-3`：更新插件并重载 Loon，确认三条脚本（Prepare / Response / Geocode cron）均已启用。

## 改坐标

默认 Apple Park（37.3349, -122.00902）。在模块参数里改：

```
latitude=39.9042&longitude=116.4074
```

参数：

| 名字 | 默认值 | 说明 |
|------|--------|------|
| `latitude` | 37.3349 | 目标纬度 |
| `longitude` | -122.00902 | 目标经度 |
| `address` | （空） | 地址搜索（Loon 插件 UI 填写，联网解析为经纬度，优先于手动经纬度） |
| `horizontalAccuracy` | 39 | 水平精度 |
| `verticalAccuracy` | 1000 | 垂直精度 |
| `altitude` | 530 | 海拔 |
| `failOpen` | true | 出错放行原数据 |
| `debug` | false | 调试日志 |

## 文件清单

```
ios-location-spoofer.sgmodule       # Shadowrocket
ios-location-spoofer-surge.sgmodule # Surge
ios-location-spoofer.lnplugin       # Loon
ios-location-spoofer.snippet        # Quantumult X
ios-location-spoofer.stoverride     # Stash
location-spoofer.js                 # 核心脚本（四平台共用）
location-spoofer-qx.js              # QX 专用
location-spoofer-config.json        # 配置样板
使用教程.md                         # 小白保姆级图文教程
location-picker/                    # 多用户控制面板（PostgreSQL + 实时地图，Docker/Coolify）
```

## 多用户控制面板

经常换定位，或者要给多个人用？项目自带 [`location-picker/`](location-picker/) 多用户控制面板：
管理员管理用户、在**实时地图**上看到每台设备（伪造位置 vs 真实位置），普通用户只看自己的设备；
每台设备通过 `configUrl` 从**你自己的面板**读取坐标 —— 无需改文件，也不再依赖 `raw.github`。

- 存储：**PostgreSQL** · 实时：**Server-Sent Events** · 部署：**Docker → Coolify**
- 完整部署、接口与环境变量说明见 **[location-picker/README.md](location-picker/README.md)**

快速开始（本地 / VPS）：

```bash
cd location-picker
ADMIN_PASS=$(openssl rand -hex 12) docker compose up --build
# → http://localhost:8080   （账号 "admin"，密码即上面的 ADMIN_PASS）
```

在手机上：面板里打开某台设备，用 **▦ QR** / **Module URL** 把模块导入 Shadowrocket，
其 `configUrl` 指向你面板的 `/loc.json?token=…`，坐标即实时生效。

## 友情链接

本项目接受 LINUX DO 社区佬友监督与反馈：[LINUX DO](https://linux.do)

数据文件 `loc.json` 自动落在 `server.js` 同目录，记录当前坐标 / 海拔 / 精度；已在 `.gitignore` 中忽略，不会被误提交进仓库。

> ⚠️ **不要把 `TOKEN` 写在命令行历史里**——推荐用 systemd 的 `Environment=` 或 `.env` + `direnv`，避免 `history` / `ps aux` 泄露。
