#ifndef CPPAD_CG_WINDOWS_SYSTEM_INCLUDED
#define CPPAD_CG_WINDOWS_SYSTEM_INCLUDED
/* --------------------------------------------------------------------------
 *  CppADCodeGen: C++ Algorithmic Differentiation with Source Code Generation:
 *    Copyright (C) 2019 Joao Leal
 *    Copyright (C) 2012 Ciengis
 *
 *  CppADCodeGen is distributed under multiple licenses:
 *
 *   - Eclipse Public License Version 1.0 (EPL1), and
 *   - GNU General Public License Version 3 (GPL3).
 *
 *  EPL1 terms and conditions can be found in the file "epl-v10.txt", while
 *  terms and conditions for the GPL3 can be found in the file "gpl3.txt".
 * ----------------------------------------------------------------------------
 * Author: Joao Leal
 */

#if CPPAD_CG_SYSTEM_WIN
#include "Shlwapi.h"
#include <cstdio>
#include <deque>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <windows.h>

namespace CppAD {
namespace cg {

/**
 * Windows system dependent functions
 */
namespace system {

template <class T>
const std::string SystemInfo<T>::DYNAMIC_LIB_EXTENSION = ".dll";

template <class T>
const std::string SystemInfo<T>::STATIC_LIB_EXTENSION = ".lib";

inline std::string getWorkingDirectory() {
  char buffer[MAX_PATH];
  auto ret = GetCurrentDirectoryA(MAX_PATH, buffer);
  if (!ret) {
    const char *error = strerror(errno);
    throw CGException("Failed to get current working directory: ", error);
  }

  return buffer;
}

inline void createFolder(const std::string &folder) {
  if (!CreateDirectory(folder.c_str(), NULL)) {
    throw CGException("Failed to create directory: ", GetLastError());
  }
}

inline std::string createPath(std::initializer_list<std::string> folders,
                              const std::string &file) {
  std::string path;

  size_t n = file.size();
  for (const std::string &folder : folders)
    n += folder.size() + 1;
  path.reserve(n);

  for (const std::string &folder : folders) {
    if (!folder.empty() && folder.back() == '/') {
      path += folder;
    } else {
      path += folder;
      path += "/";
    }
  }

  path += file;

  return path;
}

inline std::string createPath(const std::string &folder,
                              const std::string &file) {
  return createPath({folder}, file);
}

inline std::string escapePath(const std::string &path) {
  return std::string("\"") + path + "\"";
}

inline std::string filenameFromPath(const std::string &path) {
  size_t pos = path.rfind('/');
  if (pos != std::string::npos) {
    if (pos == path.size() - 1) {
      return "";
    } else {
      return path.substr(pos + 1);
    }
  } else {
    return path;
  }
}

inline std::string directoryFromPath(const std::string &path) {
  size_t found = path.find_last_of('/');
  if (found != std::string::npos) {
    return path.substr(0, found + 1);
  }
  return "./";
}

inline bool isAbsolutePath(const std::string &path) {
  if (path.empty())
    return false;

  return path[0] == '/' || path[0] == '\\';
}

inline bool isDirectory(const std::string &path) {
  return PathFileExistsA(path.c_str());
}

inline bool isFile(const std::string &path) {
  return PathFileExistsA(path.c_str());
}

inline void callExecutable(const std::string &executable,
                           const std::vector<std::string> &args,
                           std::string *stdOutErrMessage,
                           const std::string *stdInMessage) {
  int Success;
  SECURITY_ATTRIBUTES security_attributes;
  HANDLE stdout_rd = INVALID_HANDLE_VALUE;
  HANDLE stdout_wr = INVALID_HANDLE_VALUE;
  HANDLE stderr_rd = INVALID_HANDLE_VALUE;
  HANDLE stderr_wr = INVALID_HANDLE_VALUE;
  PROCESS_INFORMATION process_info;
  STARTUPINFO startup_info;
  std::thread stdout_thread;
  std::thread stderr_thread;

  security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
  security_attributes.bInheritHandle = TRUE;
  security_attributes.lpSecurityDescriptor = nullptr;

  if (!CreatePipe(&stdout_rd, &stdout_wr, &security_attributes, 0) ||
      !SetHandleInformation(stdout_rd, HANDLE_FLAG_INHERIT, 0)) {
    return;
  }

  if (!CreatePipe(&stderr_rd, &stderr_wr, &security_attributes, 0) ||
      !SetHandleInformation(stderr_rd, HANDLE_FLAG_INHERIT, 0)) {
    if (stdout_rd != INVALID_HANDLE_VALUE)
      CloseHandle(stdout_rd);
    if (stdout_wr != INVALID_HANDLE_VALUE)
      CloseHandle(stdout_wr);
    return;
  }

  ZeroMemory(&process_info, sizeof(PROCESS_INFORMATION));
  ZeroMemory(&startup_info, sizeof(STARTUPINFO));

  startup_info.cb = sizeof(STARTUPINFO);
  startup_info.hStdInput = 0;
  startup_info.hStdOutput = stdout_wr;
  startup_info.hStdError = stderr_wr;

  if (stdout_rd || stderr_rd)
    startup_info.dwFlags |= STARTF_USESTDHANDLES;

  std::stringstream cmd;
  cmd << "\"" << executable << "\"";
  for (const std::string &arg : args) {
    cmd << " " << arg;
  }

  // Make a copy because CreateProcess needs to modify string buffer
  char CmdLineStr[MAX_PATH];
  strncpy(CmdLineStr, cmd.str().c_str(), MAX_PATH);
  CmdLineStr[MAX_PATH - 1] = 0;

  Success = CreateProcess(nullptr, CmdLineStr, nullptr, nullptr, TRUE, 0,
                          nullptr, ".", &startup_info, &process_info);
  CloseHandle(stdout_wr);
  CloseHandle(stderr_wr);

  if (!Success) {
    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);
    CloseHandle(stdout_rd);
    CloseHandle(stderr_rd);
    return;
  } else {
    CloseHandle(process_info.hThread);
  }

  std::stringstream out_stream, err_stream;

  if (stdout_rd) {
    stdout_thread = std::thread([&]() {
      DWORD n;
      const size_t bufsize = 1000;
      char buffer[bufsize];
      for (;;) {
        n = 0;
        int Success = ReadFile(stdout_rd, buffer, (DWORD)bufsize, &n, nullptr);
        printf("STDERR: Success:%d n:%d\n", Success, (int)n);
        if (!Success || n == 0)
          break;
        std::string s(buffer, n);
        printf("STDOUT:(%s)\n", s.c_str());
        out_stream << s;
      }
      printf("STDOUT:BREAK!\n");
    });
  }

  if (stderr_rd) {
    stderr_thread = std::thread([&]() {
      DWORD n;
      const size_t bufsize = 1000;
      char buffer[bufsize];
      for (;;) {
        n = 0;
        int Success = ReadFile(stderr_rd, buffer, (DWORD)bufsize, &n, nullptr);
        printf("STDERR: Success:%d n:%d\n", Success, (int)n);
        if (!Success || n == 0)
          break;
        std::string s(buffer, n);
        printf("STDERR:(%s)\n", s.c_str());
        err_stream << s;
      }
      printf("STDERR:BREAK!\n");
    });
  }

  WaitForSingleObject(process_info.hProcess, INFINITE);
  int exit_code;
  if (!GetExitCodeProcess(process_info.hProcess, (DWORD *)&exit_code)) {
    exit_code = -1;
  }

  CloseHandle(process_info.hProcess);

  if (stdout_thread.joinable())
    stdout_thread.join();

  if (stderr_thread.joinable())
    stderr_thread.join();

  *stdOutErrMessage += out_stream.str();
  *stdOutErrMessage += err_stream.str();

  CloseHandle(stdout_rd);
  CloseHandle(stderr_rd);
}

} // namespace system

} // namespace cg
} // namespace CppAD

#endif
#endif
