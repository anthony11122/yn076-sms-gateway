-- YN076 短信网关 LuatOS 脚本 v2（串口版）
-- 架构：USB 虚拟串口(uart.VUART_0=ttyACM) + JSON 行协议，对接 sms_relay.py
-- 融合商家脚本包的：看门狗/内存回收/mobile.setAuto 自愈/通知队列重试思想
--
-- 协议（每行一个 JSON，\n 分帧）：
--   服务器→780 命令:  {"cmd":"send_sms","num":"10086","text":"hi"}    发短信
--                     {"cmd":"get_status"}                              查状态
--                     {"cmd":"get_traffic"}                             查流量
--                     {"cmd":"consume","kb":10}                         定量消耗流量(保号)
--                     {"cmd":"ping"}                                    心跳
--   780→服务器 响应:  {"type":"resp","req":"send_sms","ok":true,...}
--   780→服务器 推送:  {"type":"sms","num":"10086","text":"...","time":"..."}  新短信
--                     {"type":"boot","version":"..."}                    启动
--                     {"type":"call","num":"..."}                        来电（780EPM无语音，预留）

PROJECT = "sms_gateway_v2"
VERSION = "002.000.002"

log.setLevel("INFO")
log.info("main", PROJECT, VERSION)

sys = require "sys"
sysplus = require "sysplus"

-- ==================== 配置 ====================
local UART_ID = uart.VUART_0   -- USB 虚拟串口（主机侧 ttyACM）
local UART_BAUD = 115200
local LINE_BUF = ""            -- 行缓冲（\n 分帧）

-- ==================== 基础设施（融合商家包） ====================
-- 硬件看门狗：9 秒超时，3 秒喂狗
wdt.init(9000)
sys.timerLoopStart(wdt.feed, 3000)

-- 每小时回收内存
sys.timerLoopStart(function()
    collectgarbage("collect")
end, 3600000)

-- 网络自愈：SIM 自动恢复、周期小区信息、严重故障自动恢复
mobile.setAuto(10000, 300000, 8, true, 120000)

-- 流量锁: 关闭蜂窝数据上下文(PDP). 短信走信令通道不受影响;
-- 仅"定量消耗"功能会临时需要 PDP — 在 consume_cellular_data 前后开/关
if mobile.setDataEnable then mobile.setDataEnable(false) end

-- DNS
socket.setDNS(nil, 1, "119.29.29.29")
socket.setDNS(nil, 2, "223.5.5.5")

-- ==================== 串口通信层 ====================
local function serial_send(obj)
    local line = json.encode(obj)
    uart.write(UART_ID, line .. "\n")
    log.info("serial", "TX", line)
end

-- 行缓冲解析：凑满一行 JSON 就处理
local function feed_line(chunk)
    LINE_BUF = LINE_BUF .. chunk
    while true do
        local nl = LINE_BUF:find("\n", 1, true)
        if not nl then break end
        local line = LINE_BUF:sub(1, nl - 1):gsub("\r", "")
        LINE_BUF = LINE_BUF:sub(nl + 1)
        if #line > 0 then
            local ok, jdata = pcall(json.decode, line)
            if ok and jdata and jdata.cmd then
                handle_command(jdata)
            else
                log.warn("serial", "RX 无法解析:", line:sub(1, 80))
            end
        end
    end
end

-- ==================== 业务处理 ====================
local function get_traffic_info()
    local upGB, upB, downGB, downB = 0, 0, 0, 0
    if mobile and mobile.dataTraffic then
        upGB, upB, downGB, downB = mobile.dataTraffic()
    end
    local total = upGB * 1073741824 + upB + downGB * 1073741824 + downB
    return {
        total_kb = math.floor(total / 1024 * 100) / 100,
        total_bytes = total
    }
end

local function consume_cellular_data(target_kb)
    target_kb = tonumber(target_kb) or 10
    if target_kb < 1 then target_kb = 1 end
    if target_kb > 51200 then target_kb = 51200 end
    local target_bytes = math.floor(target_kb * 1024)
    -- 流量锁: 消耗功能临时开 PDP
    if mobile.setDataEnable then mobile.setDataEnable(true) end
    sys.wait(2000)
    local before = get_traffic_info()
    local tmp_file = "/traffic_tmp.bin"
    local url1 = "http://httpbin.luatos.com/bytes/" .. tostring(target_bytes)
    local url2 = "http://speed.cloudflare.com/__down?bytes=" .. tostring(target_bytes)
    local opts = { adapter = socket.LWIP_GP, timeout = 25000, dst = tmp_file }
    local code, headers, body_size = http.request("GET", url1, nil, nil, opts).wait()
    if code ~= 200 then
        code, headers, body_size = http.request("GET", url2, nil, nil, opts).wait()
    end
    if io.exists and io.exists(tmp_file) then os.remove(tmp_file) end
    local after = get_traffic_info()
    local delta = math.floor((after.total_kb - before.total_kb) * 100) / 100
    if delta <= 0 and body_size and body_size > 0 then
        delta = math.floor((body_size / 1024) * 100) / 100
    end
    -- 流量锁: 消耗完立即关 PDP
    if mobile.setDataEnable then mobile.setDataEnable(false) end
    return { ok = (code == 200), http_code = code, requested_kb = target_kb, consumed_kb = delta, total_kb = after.total_kb }
end

-- 短信发送队列（串口命令可能并发，串行化处理）
local SMS_QUEUE = {}
local sending = false

local function sms_send_worker()
    while true do
        sys.waitUntil("SMS_QUEUE_NEW")
        while #SMS_QUEUE > 0 do
            local item = table.remove(SMS_QUEUE, 1)
            item.status = "sending"
            local result = sms.send(item.num, item.text)
            if result then
                local _, ok = sys.waitUntil("SMS_SENT", 15000)
                item.status = ok and "sent" or "failed"
            else
                item.status = "failed"
            end
            log.info("sms", "发送", item.num, item.status)
            serial_send({ type = "resp", req = "send_sms", id = item.id, ok = (item.status == "sent"), status = item.status })
        end
    end
end

-- ==================== 命令分发 ====================
function handle_command(jdata)
    log.info("serial", "RX", json.encode(jdata))

    if jdata.cmd == "ping" then
        serial_send({ type = "resp", req = "ping", ok = true, ts = os.time() })

    elseif jdata.cmd == "send_sms" then
        if jdata.num and jdata.text then
            local item = { id = jdata.id or tostring(os.time()), num = jdata.num, text = jdata.text, status = "pending" }
            table.insert(SMS_QUEUE, item)
            sys.publish("SMS_QUEUE_NEW")
            serial_send({ type = "resp", req = "send_sms", id = item.id, ok = true, status = "queued" })
        else
            serial_send({ type = "resp", req = "send_sms", ok = false, error = "missing num/text" })
        end

    elseif jdata.cmd == "get_status" then
        local oknum, num = pcall(mobile.number)
        serial_send({
            type = "resp", req = "get_status", ok = true,
            project = PROJECT, version = VERSION,
            csq = mobile.csq(), iccid = mobile.iccid(), imsi = mobile.imsi(),
            number = (oknum and num) and num or "",
            net_status = mobile.status(),
            traffic = get_traffic_info(),
            queue_len = #SMS_QUEUE,
            uptime = mcu.ticks()
        })

    elseif jdata.cmd == "get_traffic" then
        serial_send({ type = "resp", req = "get_traffic", ok = true, traffic = get_traffic_info() })

    elseif jdata.cmd == "consume" then
        sys.taskInit(function()
            local r = consume_cellular_data(jdata.kb)
            serial_send({ type = "resp", req = "consume", ok = r.ok, result = r })
        end)

    elseif jdata.cmd == "restart" then
        serial_send({ type = "resp", req = "restart", ok = true })
        sys.wait(500)
        rtos.restart()
    else
        serial_send({ type = "resp", req = jdata.cmd, ok = false, error = "unknown cmd" })
    end
end

-- ==================== 短信接收（推送模式） ====================
sms.setNewSmsCb(function(sender_number, sms_content, m)
    local time = string.format("%d-%02d-%02d %02d:%02d:%02d", m.year + 2000, m.mon, m.day, m.hour, m.min, m.sec)
    log.info("sms", "收到", sender_number, sms_content)
    -- 立即经串口推送给服务器（无需轮询！）
    serial_send({ type = "sms", num = sender_number, text = sms_content, time = time })
end)

-- ==================== 初始化 ====================
uart.setup(UART_ID, UART_BAUD, 8, 1, uart.NONE)
uart.on(UART_ID, "receive", function(id, len)
    local data = uart.read(id, len)
    if data and #data > 0 then
        feed_line(data)
    end
end)

sys.taskInit(sms_send_worker)

-- 启动握手（服务器可据此判断 780 就绪）
sys.timerStart(function()
    serial_send({ type = "boot", project = PROJECT, version = VERSION, reason = pm.lastReson() })
end, 3000)

-- 每 60 秒心跳（服务器可检测链路活性）
sys.timerLoopStart(function()
    serial_send({ type = "heartbeat", ts = os.time(), traffic = get_traffic_info(), csq = mobile.csq() })
end, 60000)

-- 流量锁: 不做 sntp 公网校时(短信时间戳用基站下发; 少量流量也不走)
-- 如需校时, 通过面板 get_status 时的基站时间足够

sys.run()
