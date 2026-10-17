// ============================================================================
//  McpClient.cpp —— Cheat Engine MCP Bridge 客户端实现
//  Named Pipe / TCP 双模式，4 字节小端长度前缀 + JSON-RPC 帧
// ============================================================================
#include "McpClient.h"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

namespace ce {

static bool WriteAllPipe(HANDLE h, const void* buf, DWORD size) {
  DWORD written = 0;
  const char* p = (const char*)buf;
  while (written < size) {
    DWORD w = 0;
    if (!::WriteFile(h, p + written, size - written, &w, nullptr) || w == 0) return false;
    written += w;
  }
  return true;
}

static bool ReadAllPipe(HANDLE h, void* buf, DWORD size) {
  DWORD got = 0;
  char* p = (char*)buf;
  while (got < size) {
    DWORD r = 0;
    if (!::ReadFile(h, p + got, size - got, &r, nullptr) || r == 0) return false;
    got += r;
  }
  return true;
}

static bool WriteAllSock(int s, const void* buf, int size) {
  const char* p = (const char*)buf;
  int sent = 0;
  while (sent < size) {
    int n = ::send(s, p + sent, size - sent, 0);
    if (n <= 0) return false;
    sent += n;
  }
  return true;
}

static bool ReadAllSock(int s, void* buf, int size) {
  char* p = (char*)buf;
  int got = 0;
  while (got < size) {
    int n = ::recv(s, p + got, size - got, 0);
    if (n <= 0) return false;
    got += n;
  }
  return true;
}

McpClient::~McpClient() { Disconnect(); }

bool McpClient::Connect(const Config& cfg, std::string* error) {
  Disconnect();
  cfg_ = cfg;

  if (cfg.useTcp) {
    WSADATA wsa{};
    ::WSAStartup(MAKEWORD(2, 2), &wsa);
    sock_ = (int)::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_ < 0) { if (error) *error = "socket 创建失败"; return false; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = ::htons((u_short)cfg.port);
    ::inet_pton(AF_INET, cfg.host.c_str(), &addr.sin_addr);
    if (::connect(sock_, (sockaddr*)&addr, sizeof(addr)) != 0) {
      if (error) *error = "TCP 连接失败 " + cfg.host + ":" + std::to_string(cfg.port) +
                          "（是否已运行 ce_tcp_relay.py?）";
      ::closesocket(sock_); sock_ = -1;
      return false;
    }
    int nodelay = 1;
    ::setsockopt(sock_, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));
    sock_ = sock_; // keep
  } else {
    HANDLE h = ::CreateFileA(cfg.pipeName.c_str(), GENERIC_READ | GENERIC_WRITE,
                             0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
      DWORD e = ::GetLastError();
      if (error) {
        if (e == ERROR_PIPE_BUSY) *error = "管道忙（CE 桥正在被其他客户端使用）";
        else if (e == ERROR_FILE_NOT_FOUND) *error = "管道不存在: " + cfg.pipeName +
                   "（是否已在 Cheat Engine 中执行 ce_mcp_bridge.lua?）";
        else *error = "连接管道失败，Win32 错误 " + std::to_string(e);
      }
      return false;
    }
    pipe_ = h;
  }

  connected_ = true;
  if (statusCb_) statusCb_(true);
  return true;
}

void McpClient::Disconnect() {
  if (!connected_ && pipe_ == nullptr && sock_ < 0) return;
  connected_ = false;
  if (statusCb_) statusCb_(false);
  if (pipe_) { ::CloseHandle((HANDLE)pipe_); pipe_ = nullptr; }
  if (sock_ >= 0) { ::closesocket(sock_); sock_ = -1; }
}

bool McpClient::SendFrame(const std::string& json, std::string* error) {
  if (!connected_) { if (error) *error = "未连接"; return false; }
  uint32_t len = (uint32_t)json.size();
  char hdr[4];
  std::memcpy(hdr, &len, 4);   // 小端 (x64 本身小端)
  std::lock_guard<std::mutex> lk(sendMtx_);
  if (cfg_.useTcp) {
    if (!WriteAllSock(sock_, hdr, 4) || !WriteAllSock(sock_, json.data(), (int)json.size())) {
      if (error) *error = "TCP 发送失败";
      return false;
    }
  } else {
    if (!WriteAllPipe((HANDLE)pipe_, hdr, 4) ||
        !WriteAllPipe((HANDLE)pipe_, json.data(), (DWORD)json.size())) {
      if (error) *error = "管道写入失败";
      return false;
    }
  }
  return true;
}

bool McpClient::RecvFrame(std::string* json, int timeoutMs, std::string* error) {
  if (!connected_) { if (error) *error = "未连接"; return false; }
  char hdr[4];
  // 简化超时：TCP 用 select；管道用 PeekNamedPipe 轮询
  if (cfg_.useTcp) {
    fd_set rset; FD_ZERO(&rset); FD_SET((SOCKET)sock_, &rset);
    timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
    if (::select(0, &rset, nullptr, nullptr, &tv) <= 0) {
      if (error) *error = "等待响应超时";
      return false;
    }
    if (!ReadAllSock(sock_, hdr, 4) || !ReadAllSock(sock_, hdr, 0)) { /* second no-op */ }
    if (!ReadAllSock(sock_, hdr, 4)) { if (error) *error = "TCP 读取头失败"; return false; }
  } else {
    // 管道轮询等待数据
    DWORD avail = 0;
    DWORD deadline = ::GetTickCount() + (DWORD)timeoutMs;
    for (;;) {
      if (!::PeekNamedPipe((HANDLE)pipe_, nullptr, 0, nullptr, &avail, nullptr)) {
        if (error) *error = "管道已断开";
        connected_ = false;
        return false;
      }
      if (avail >= 4) break;
      if (::GetTickCount() > deadline) { if (error) *error = "等待响应超时"; return false; }
      ::Sleep(10);
    }
    if (!ReadAllPipe((HANDLE)pipe_, hdr, 4)) { if (error) *error = "管道读取头失败"; return false; }
  }
  uint32_t len = 0;
  std::memcpy(&len, hdr, 4);
  if (len > 64 * 1024 * 1024) { if (error) *error = "响应帧过大"; return false; }
  json->resize(len);
  if (cfg_.useTcp) {
    if (!ReadAllSock(sock_, &(*json)[0], (int)len)) { if (error) *error = "TCP 读取体失败"; return false; }
  } else {
    if (!ReadAllPipe((HANDLE)pipe_, &(*json)[0], len)) { if (error) *error = "管道读取体失败"; return false; }
  }
  return true;
}

bool McpClient::Send(const std::string& method, const std::string& paramsJson,
                     std::string* error) {
  std::string req = "{\"method\":\"" + method + "\",\"params\":" + paramsJson + "}";
  return SendFrame(req, error);
}

bool McpClient::SendWait(const std::string& method, const std::string& paramsJson,
                         std::string* response, int timeoutMs, std::string* error) {
  std::string req = "{\"method\":\"" + method + "\",\"params\":" + paramsJson + "}";
  if (!SendFrame(req, error)) return false;
  return RecvFrame(response, timeoutMs, error);
}

} // namespace ce
