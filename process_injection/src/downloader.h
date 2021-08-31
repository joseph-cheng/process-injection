#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <utility>
#include <windows.h>
#include <ws2tcpip.h>
#ifdef DEBUG
#include <stdio.h>
#endif

#pragma comment(lib, "Ws2_32.lib")

int setup_winsock();

SOCKET setup_socket(PCSTR ip_address, PCSTR port);

std::pair<BYTE *, size_t> download(PCSTR ip_address, PCSTR port);
