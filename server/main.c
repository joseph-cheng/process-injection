#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

struct buf_with_size {
  char *buf;
  size_t size;
};

struct buf_with_size load_file(const char *filename) {
  struct buf_with_size to_return = {NULL, 0};
  // open file
  FILE *fp = fopen(filename, "r");
  if (fp == NULL) {
    printf("Failed to open file %s\n", filename);
    return to_return;
  }

  // get file size
  if (fseek(fp, 0L, SEEK_END) != 0) {
    printf("Failed to seek to end of file\n");
    return to_return;
  }

  long file_size = ftell(fp);
  if (file_size == -1) {
    printf("Failed to get file size\n");
    return to_return;
  }

  char *buffer = malloc(sizeof(char) * file_size);

  if (fseek(fp, 0L, SEEK_SET) != 0) {
    printf("Failed to seek to start of file\n");
    return to_return;
  }

  size_t len = fread(buffer, sizeof(char), file_size, fp);
  if (ferror(fp) != 0) {
    printf("Failed to read file\n");
    return to_return;
  }
  fclose(fp);
  to_return.buf = buffer;
  to_return.size = len;
  return to_return;
}

int main(int argc, char **argv) {
  if (argc != 4) {
    printf("Usage: server file_to_serve ip_address_to_bind port\n");
    return 1;
  }
  int server_sock, client_sock;
  struct sockaddr_in server, client;

  // set up server socket
  server_sock = socket(AF_INET, SOCK_STREAM, 0);

  if (server_sock == -1) {
    printf("Failed to create socket\n");
    return 2;
  }

  server.sin_family = AF_INET;
  inet_aton(argv[2], &server.sin_addr);
  server.sin_port = htons(atoi(argv[3]));

  if (bind(server_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
    printf("Failed to bind socket: %d\n", errno);
    return 3;
  }

  struct buf_with_size file = load_file(argv[1]);

  if (listen(server_sock, 3) == -1) {
    printf("Failed to begin listening: %d\n", errno);
    return 4;
  }
  size_t c = sizeof(struct sockaddr_in);
  printf("Waiting for connection...\n");
  while (1) {
    // accept connection from client
    client_sock =
        accept(server_sock, (struct sockaddr *)&client, (socklen_t *)&c);
    if (client_sock < 0) {
      printf("Failed to accept connection\n");
      continue;
    }

    printf("Connection accepted\n");
    printf("Writing size of file...\n");
    // write file size and file buf
    unsigned int file_size = htonl(file.size);
    write(client_sock, &file_size, sizeof(file_size));
    printf("Writing file...\n");
    write(client_sock, file.buf, file.size);

    close(client_sock);
    printf("Done!\n");
  }
  return 0;
}
