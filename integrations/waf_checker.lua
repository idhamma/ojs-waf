-- waf_checker.lua
-- ML-Based WAF Checker — Nginx/Lua Integration (Userspace)
--
-- Dijalankan di dalam Docker container OJS via OpenResty.
-- Mencegat setiap HTTP request, mengirim payload ke Python sidecar
-- untuk ML inference, dan mengeksekusi keputusan:
--   PASS  → request diteruskan ke PHP-FPM (OJS)
--   BLOCK → koneksi langsung di-DROP tanpa response (ngx.exit 444)
--
-- Sidecar berjalan di host, diakses via Docker gateway IP (172.19.0.1:9999)

local cjson = require("cjson.safe")

-- ============================================================================
-- Configuration
-- ============================================================================

-- Sidecar agent address: host gateway dari sudut pandang container
local WAF_AGENT_HOST = os.getenv("WAF_AGENT_HOST") or "172.19.0.1"
local WAF_AGENT_PORT = tonumber(os.getenv("WAF_AGENT_PORT")) or 9999
local WAF_TIMEOUT_MS = 2000
local MAX_BODY_SIZE  = 16384   -- 16KB body dikirim ke sidecar

-- ============================================================================
-- Logger
-- ============================================================================

local function log_info(msg)
    ngx.log(ngx.INFO, "[WAF] " .. msg)
end

local function log_error(msg)
    ngx.log(ngx.ERR, "[WAF-ERROR] " .. msg)
end

-- ============================================================================
-- Helpers
-- ============================================================================

local function get_request_id()
    local rid = ngx.var.request_id
    if rid and rid ~= "" then
        return rid
    end
    return ngx.md5(tostring(ngx.now()) .. (ngx.var.remote_addr or "") .. tostring(math.random(100000, 999999)))
end

local function extract_request_body()
    ngx.req.read_body()

    local body = ngx.req.get_body_data()
    if not body then
        local temp_file = ngx.req.get_body_file()
        if temp_file then
            local f = io.open(temp_file, "rb")
            if f then
                body = f:read(MAX_BODY_SIZE)
                f:close()
            end
        end
    end

    body = body or ""
    if #body > MAX_BODY_SIZE then
        body = string.sub(body, 1, MAX_BODY_SIZE)
    end
    return body
end

local function get_headers_table()
    local headers = ngx.req.get_headers()
    local result = {}

    local SENSITIVE = {
        ["x-csrf-token"] = true,
        ["x-api-key"]    = true,
    }

    for key, value in pairs(headers) do
        local lower_key = key:lower()
        if lower_key ~= "content-length" and lower_key ~= "transfer-encoding" then
            if SENSITIVE[lower_key] then
                result[key] = "[MASKED]"
            elseif type(value) == "table" then
                result[key] = table.concat(value, ", ")
            else
                result[key] = value
            end
        end
    end

    return result
end

local function should_bypass_waf(uri, method)
    -- Static assets dan health checks tidak perlu dicek WAF
    local bypass_patterns = {
        "^/health$",
        "^/robots%.txt$",
        "^/favicon%.ico$",
    }

    for _, pattern in ipairs(bypass_patterns) do
        if ngx.re.match(uri, pattern) then
            return true
        end
    end

    if method == "OPTIONS" then
        return true
    end

    return false
end

-- ============================================================================
-- Komunikasi ke Sidecar Agent via TCP
-- ============================================================================

local function send_to_waf_agent(request_data)
    local sock = ngx.socket.tcp()
    if not sock then
        log_error("Failed to create cosocket")
        return nil, "socket_error"
    end

    sock:settimeout(WAF_TIMEOUT_MS)

    -- Connect ke sidecar di host
    local ok, err = sock:connect(WAF_AGENT_HOST, WAF_AGENT_PORT)
    if not ok then
        log_error("Cannot connect to sidecar ("
                  .. WAF_AGENT_HOST .. ":" .. WAF_AGENT_PORT
                  .. "): " .. tostring(err))
        return nil, "connection_error"
    end

    -- Encode dan kirim sebagai JSONL
    local payload, encode_err = cjson.encode(request_data)
    if not payload then
        log_error("JSON encode error: " .. tostring(encode_err))
        sock:close()
        return nil, "encode_error"
    end

    local bytes, send_err = sock:send(payload .. "\n")
    if not bytes then
        log_error("Send error: " .. tostring(send_err))
        sock:close()
        return nil, "send_error"
    end

    -- Baca response (satu baris JSON)
    local line, read_err = sock:receive("*l")
    sock:close()

    if not line then
        log_error("No response from sidecar: " .. tostring(read_err))
        return nil, "read_error"
    end

    local result, decode_err = cjson.decode(line)
    if not result then
        log_error("JSON decode error: " .. tostring(decode_err))
        return nil, "decode_error"
    end

    return result, nil
end

-- ============================================================================
-- Main WAF Logic
-- ============================================================================

local function check_request()
    local request_id = get_request_id()
    local method = ngx.var.request_method
    local uri = ngx.var.uri
    local source_ip = ngx.var.remote_addr
    local query_string_val = ngx.var.query_string or ""

    -- Full URI dengan query string
    local full_uri = uri
    if query_string_val ~= "" then
        full_uri = uri .. "?" .. query_string_val
    end

    -- Bypass check
    if should_bypass_waf(uri, method) then
        return  -- PASS, lanjut ke content phase
    end

    -- Extract request data
    local headers = get_headers_table()
    local body = extract_request_body()

    local raw_headers = ngx.req.get_headers()

    -- Susun REQUEST_CHECK
    local request_data = {
        type          = "REQUEST_CHECK",
        request_id    = request_id,
        timestamp     = ngx.http_time(ngx.time()),
        method        = method,
        uri           = full_uri,
        headers       = headers,
        body          = body,
        source_ip     = source_ip,
        source_port   = tonumber(ngx.var.remote_port) or 0,
        server_ip     = ngx.var.server_addr or "0.0.0.0",
        server_port   = tonumber(ngx.var.server_port) or 0,
        query_string  = query_string_val,
        cookie        = raw_headers["cookie"] or "",
        authorization = raw_headers["authorization"] or "",
        x_forwarded_for = raw_headers["x-forwarded-for"] or "",
    }

    -- Kirim ke sidecar
    local waf_response, waf_err = send_to_waf_agent(request_data)

    if not waf_response then
        -- Fail-open: jika sidecar tidak tersedia, izinkan request
        log_error("WAF check failed (" .. tostring(waf_err) .. "), fail-open → PASS")
        return
    end

    local decision     = waf_response.decision or "PASS"
    local threat_score = waf_response.threat_score or 0
    local attack_type  = waf_response.attack_type or "NONE"

    log_info(decision .. " " .. method .. " " .. full_uri
             .. " score=" .. string.format("%.3f", threat_score)
             .. " type=" .. attack_type
             .. " ip=" .. source_ip
             .. " id=" .. request_id)

    if decision == "BLOCK" then
        -- DROP: putuskan koneksi langsung tanpa mengirim response apapun.
        -- Status 444 adalah kode khusus Nginx yang menutup koneksi tanpa
        -- mengirim HTTP response. Ini menghemat resource dan tidak memberi
        -- informasi apapun kepada attacker.
        log_info("DROP " .. full_uri .. " — " .. attack_type
                 .. " score=" .. string.format("%.3f", threat_score))
        return ngx.exit(444)
    end

    -- PASS: request diteruskan ke PHP-FPM (upstream OJS)
end

-- ============================================================================
-- Execute
-- ============================================================================

check_request()
