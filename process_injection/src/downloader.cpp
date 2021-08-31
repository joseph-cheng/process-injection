#include "downloader.h"
#include <utility>

int setup_winsock() {
  WSADATA wsadata;
  int result = WSAStartup(MAKEWORD(2, 2), &wsadata);
  if (result != 0) {
#ifdef DEBUG
    printf("WSAStartup failed: %d\n", result);
#endif
    return 1;
  }
  return 0;
}

SOCKET setup_socket(PCSTR ip_address, PCSTR port) {
  int result;
  struct addrinfo *info = NULL;
  struct addrinfo hints;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  // resolve host:port
  // have to memset to 0 or else getaddrinfo gets confused
  memset(&hints, 0, sizeof(hints));
  result = getaddrinfo(ip_address, port, &hints, &info);
  if (result != 0) {
#ifdef DEBUG
    printf("getaddrinfo failed: %d\n", result);
#endif
    return INVALID_SOCKET;
  }

  SOCKET sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
  if (sock == INVALID_SOCKET) {
#ifdef DEBUG
    printf("Failed to create socket: %d\n", WSAGetLastError());
#endif
    return INVALID_SOCKET;
  }

  result = connect(sock, info->ai_addr, (int)info->ai_addrlen);
  if (result == SOCKET_ERROR) {
#ifdef DEBUG
    printf("Failed to connect: %d\n", WSAGetLastError());
#endif
    closesocket(sock);
    sock = INVALID_SOCKET;
    return sock;
  }

  freeaddrinfo(info);
  return sock;
}

std::pair<BYTE *, size_t> download(PCSTR ip_address, PCSTR port) {
  int result;
  result = setup_winsock();
  std::pair<BYTE *, size_t> to_return = std::pair<BYTE *, size_t>(NULL, 0);
  if (result != 0) {
#ifdef DEBUG
    printf("Failed to setup winsock: %d\n", WSAGetLastError());
#endif
    return to_return;
  }

  SOCKET sock = setup_socket(ip_address, port);
  if (sock == INVALID_SOCKET) {
#ifdef DEBUG
    printf("Failed to create socket: %d\n", WSAGetLastError());
#endif
    WSACleanup();
    return to_return;
  }

  int size_of_dll;
  int bytes_received = 0;
  int new_bytes_received;

  // loop until we read all of the int
  while (bytes_received < sizeof(int)) {
    new_bytes_received = recv(sock, ((char *)(&size_of_dll) + bytes_received),
                              sizeof(int) - bytes_received, 0);
    if (new_bytes_received == 0) {
#ifdef DEBUG
      printf("recv() failed, socket was closed gracefully.\n");
#endif
      return to_return;
    } else if (new_bytes_received == SOCKET_ERROR) {
#ifdef DEBUG
      printf("recv() failed, socket error: %d\n", WSAGetLastError());
#endif
      return to_return;
    }
    bytes_received += new_bytes_received;
  }

  // make endianness correct
  size_of_dll = ntohl(size_of_dll);

  // allocate space for dll
  BYTE *dll_buf = new BYTE[size_of_dll];
  bytes_received = 0;

  // loop until we've read the entire dll
  while (bytes_received < size_of_dll) {
    new_bytes_received = recv(sock, (char *)(dll_buf + bytes_received),
                              size_of_dll - bytes_received, 0);
    if (new_bytes_received == 0) {
#ifdef DEBUG
      printf("recv() failed, socket was closed gracefully.\n");
#endif
      return to_return;
    } else if (new_bytes_received == SOCKET_ERROR) {
#ifdef DEBUG
      printf("recv() failed, socket error: %d\n", WSAGetLastError());
#endif
      return to_return;
    }
    bytes_received += new_bytes_received;
  }
  to_return.first = dll_buf;
  to_return.second = size_of_dll;
  return to_return;
}
