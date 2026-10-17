#pragma once
// ============================================================================
//  McpClient.h —— 连接 Cheat Engine MCP Bridge 的客户端
//  协议：Named Pipe \\.\pipe\CE_MCP_Bridge_v99（或 TCP relay 127.0.0.1:9876）
//  帧格式：4 字节小端长度前缀 + JSON-RPC 文本（与 mcp_cheatengine.py 一致）
// ============================================================================
#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <deque>

namespace ce {

class McpClient {
public:
  struct Config {
    bool useTcp = false;          // false=NamedPipe, true=TCP relay
    std::string host = "127.0.0.1";
    int port = 9876;
    std::string pipeName = "\\\\.\\pipe\\CE_MCP_Bridge_v99";
  };

  // 状态回调：connected / disconnected / 响应文本
  using StatusCb = std::function<void(bool connected)>;
  using LogCb = std::function<void(const std::string& line)>;

  ~McpClient();

  bool Connect(const Config& cfg, std::string* error = nullptr);
  void Disconnect();
  bool IsConnected() const { return connected_; }
  const Config& config() const { return cfg_; }

  // 异步发送方法调用（JSON-RPC 风格 params），结果通过 LogCb 回来
  bool Send(const std::string& method, const std::string& paramsJson = "{}",
            std::string* error = nullptr);

  // 同步发送并等待响应（简单场景用）
  bool SendWait(const std::string& method, const std::string& paramsJson,
                std::string* response, int timeoutMs = 5000, std::string* error = nullptr);

  void SetStatusCb(StatusCb cb) { statusCb_ = std::move(cb); }
  void SetLogCb(LogCb cb) { logCb_ = std::move(cb); }

private:
  bool SendFrame(const std::string& json, std::string* error);
  bool RecvFrame(std::string* json, int timeoutMs, std::string* error);
  void IoLoop();

  Config cfg_;
  void* pipe_ = nullptr;               // HANDLE
  int sock_ = -1;                      // TCP 模式
  std::atomic<bool> connected_{false};
  std::thread ioThread_;
  std::mutex sendMtx_;
  StatusCb statusCb_;
  LogCb logCb_;
};

} // namespace ce
