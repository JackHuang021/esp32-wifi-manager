# esp32-wifi-manager

该组件原作者[tonyp7/esp32-wifi-manager](https://github.com/tonyp7/esp32-wifi-manager)，原作者已经不再进行维护，在原作基础上适配了最新的esp-idf sdk，解决了一些bug，原始的[README链接](README_ori.md)

*esp32-wifi-manager* 是一个纯C的esp-idf组件，该组件可通过web端配置和查看wifi连接信息

*esp32-wifi-manager* 将在启动时自动尝试重新连接到之前保存的网络，如果找不到保存的wifi，它将启动自己的AP接入点，您可以通过该接入点进入到web端管理和连接到ESP32的wifi网络，成功连接后，软件将在一段时间后（默认为1分钟）自动关闭AP接入点。

*esp32-wifi-manager* 支持esp-idf 4.2及以上的版本

# 目录
- [esp32-wifi-manager](#esp32-wifi-manager)
- [目录](#目录)
- [演示照片](#演示照片)
- [使用](#使用)
  - [前提条件](#前提条件)
  - [快速开始](#快速开始)
  - [配置](#配置)
- [将esp32-wifi-manager加入到您的代码](#将esp32-wifi-manager加入到您的代码)
  - [与esp32-wifi-manager集成](#与esp32-wifi-manager集成)
    - [事件列表](#事件列表)
    - [事件参数](#事件参数)
  - [与http服务器交互](#与http服务器交互)
  - [线程安全和NVS访问](#线程安全和nvs访问)
- [License](#license)
   

# 演示照片
![](https://raw.githubusercontent.com/JackHuang021/images/master/20240603230034.png)

# 使用

## 前提条件
- esp-idf **4.2及以上版本**
- esp32系列芯片

## 快速开始

clone仓库
```bash 
git clone https://github.com/JackHuang021/esp32-wifi-manager.git
```

进入到 *examples* 下的 *default_demo* 工程目录

```bash
cd esp32-wifi-manager/examples/default_demo
```

通过*idf*工具编译烧录到esp32
```bash
idf.py build flash monitor
```

烧录完成后，使用任何具有wifi功能的设备，您都会看到一个名为*esp32*的新wifi接入点。使用默认密码*esp32pwd*连接到它。如果你的设备上没有弹出专属入口，你可以访问默认IP地址：http://10.10.0.1

## 配置

通过 *menuconfig* 进行配置
```bash
idf.py menuconfig
```

进入到 Component config -> Wifi Manager Configuration，可以看到下面的界面：
![esp32-wifi-manager-menuconfig](https://raw.githubusercontent.com/JackHuang021/images/master/20240603230323.png "menuconfig screen")

您可以更改AP接入点的的ssid和密码，但强烈建议保留默认值。您的密码长度应该在8到63个字符之间，以符合WPA2标准。如果密码设置为空值或长度小于8个字符，则*esp32-wifi-manager*会将其接入点创建为开放的wifi网络。

您还可以更改各种计时器的值，例如，一旦建立连接，接入点关闭所需的时间（默认值：60000ms）。将此计时器设置为0，将看不到连接wifi成功的反馈，关闭AP接入点将立即终止web端的当前会话，请谨慎设置。

最后，您可以通过将默认URL地址 ”*/*“ 更改为其它地址，例如 ”*/wifimanager/*“，选择将 *esp32-wifi-manager* 重新定位到不同的URL，如果您希望自己的web应用程序与 *esp32-wifi-manager* 的网页共存，此功能尤其有用。

# 将esp32-wifi-manager加入到您的代码

为了在您的esp-idf项目中有效地使用 *esp32-wifi-manager* ，请将整个 *esp32-wifi-manager* 仓库复制（或git clone）到 *components* 子文件夹中。

工程目录结构应该如下所示:

  - project_folder
    - build
    - components
      - esp32-wifi-manager
    - main
      - main.c

完成后，您需要编辑项目根目录下的 *CMakeLists.txt* 文件，以注册 *components* 文件夹，通过添加以下行来完成的：

```cmake
set(EXTRA_COMPONENTS_DIRS components/)
```

通常 *CMakeLists.txt* 的内容如下所示
```cmake
cmake_minimum_required(VERSION 3.5)
set(EXTRA_COMPONENT_DIRS components/)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(name_of_your_project)
```


完成后，您现在可以在用户代码中添加头文件：
```c
#include "wifi_manager.h"
```

您现在需要做的就是在代码中调用 `wifi_manager_start()` ，如果您不清楚怎么使用，请参阅[examples/default_demo](examples/default_demo)。


## 与esp32-wifi-manager集成

实际上，有三种不同的方法可以将 esp32-wifi-manager 集成到您的代码中，并与之交互：
* 在你的代码中轮询 wifi 连接状态
* 使用事件回调
* 直接修改 *esp32-wifi-manager* 代码以满足您的需求

**事件回调**是使用 *esp32-wifi-manager* 最简洁的方式，也是推荐的方式。一个典型的用例是当 *esp32-wifi-manager* 最终连接到接入点时收到通知。为了做到这一点，您只需定义一个回调函数：

```c
void cb_connection_ok(void *pvParameter){
	ESP_LOGI(TAG, "I have a connection!");
}
```

然后只需通过调用以下命令进行事件注册：

```c
wifi_manager_set_callback(WM_EVENT_STA_GOT_IP, &cb_connection_ok);
```

现在每次触发事件时它都会调用此函数。[examples/default_demo](examples/default_demo)包含使用回调的示例代码。

### 事件列表

可以添加回调的事件列表由 *wifi_manager.h* 中的 *message_code_t* 定义。它们如下：

* WM_ORDER_START_HTTP_SERVER
* WM_ORDER_STOP_HTTP_SERVER
* WM_ORDER_START_DNS_SERVICE
* WM_ORDER_STOP_DNS_SERVICE
* WM_ORDER_START_WIFI_SCAN
* WM_ORDER_LOAD_AND_RESTORE_STA
* WM_ORDER_CONNECT_STA
* WM_ORDER_DISCONNECT_STA
* WM_ORDER_START_AP
* WM_EVENT_STA_DISCONNECTED
* WM_EVENT_SCAN_DONE
* WM_EVENT_STA_GOT_IP
* WM_ORDER_STOP_AP

实际上，跟踪 *WM_EVENT_STA_GOT_IP* 和 *WM_EVENT_STA_DISCONNECTED* 是了解您的 esp32 是否有连接的关键。在使用 *esp32-wifi-manager* 的典型应用程序中，其他消息大多可以忽略。

### 事件参数

回调函数参数包含一个 `void` 指针，对于大多数事件，此参数为空，少数选定事件具有可供用户代码利用的附加数据，如下：

* `WM_EVENT_SCAN_DONE` 与 `wifi_event_sta_scan_done_t *` 对象一起发送。
* `WM_EVENT_STA_DISCONNECTED` 与 `wifi_event_sta_disconnected_t *` 对象一起发送。
* `WM_EVENT_STA_GOT_IP` 与 `ip_event_got_ip_t *` 对象一起发送。

这些对象是标准的 esp-idf 结构，并在[官方页面](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/network/esp_wifi.html)有记录。

[examples/default_demo](examples/default_demo)演示了如何读取 `ip_event_got_ip_t` 对象来访问分配给 esp32 的 IP 地址。

## 与http服务器交互

由于 *esp32-wifi-manager* 生成了自己的 http 服务器，您可能希望扩展此服务器以在应用程序中提供您自己的页面。 可以使用标准 esp_http_server 来注册您自己的 URL 处理程序来实现这一点。

```c
esp_err_t my_custom_handler(httpd_req_t *req){
```

然后通过以下方式注册处理程序

```c
http_app_set_handler_hook(HTTP_GET, &my_custom_handler);
```

[examples/http_hook](examples/http_hook) 包含了一个 `/helloworld` 注册网页的示例

## 线程安全和NVS访问

*esp32-wifi-manager* 访问非易失性存储以将其wifi配置信息存储并加载到专用命名空间 `espwifimgr` 中。如果您想确保永远不会与对 NVS 的并发访问发生冲突，您可以包含 `nvs_sync.h` 并使用 `nvs_sync_lock()` 和 `nvs_sync_unlock()` 的调用。

```c
nvs_handle handle;

if(nvs_sync_lock( portMAX_DELAY )){  
    if(nvs_open(wifi_manager_nvs_namespace, NVS_READWRITE, &handle) == ESP_OK){
        /* do something with NVS */
	nvs_close(handle);
    }
    nvs_sync_unlock();
}
```
`nvs_sync_lock` 等待作为参数发送给它的 `ticks` 数以获取互斥锁，建议使用 portMAX_DELAY，实际上，`nvs_sync_lock()` 几乎永远不会等待。


# License
*esp32-wifi-manager* 使用了MIT LICENSE。因此，只要您保留原始版权，它就可以包含在任何项目中，无论是否是商业项目。请您务必阅读LICENSE文件。