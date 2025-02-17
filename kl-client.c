#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "kl.h"

int main(void) {
  int fd, ret;
  char log_buffer[MAX_BUF_LEN];
  struct kl_log_req log_req;
  FILE *log_file;

  log_file = fopen(KL_LOG_PATH, "a");
  if (!log_file) {
    perror("fopen error");
    exit(EXIT_FAILURE);
  }

  fd = open(KL_PATH, O_RDWR);
  if (fd < 0) {
    perror("device open error");
    fclose(log_file);
    exit(EXIT_FAILURE);
  }

  /* register user log buffer */
  log_req.buf = log_buffer;
  log_req.len = MAX_BUF_LEN;
  ret = ioctl(fd, KL_CMD_SET_LOG_BUFFER, &log_req);
  if (ret < 0) {
    fprintf(stderr, "ioctl KL_CMD_SET_LOG_BUFFER failed: %s\n", strerror(errno));
    close(fd);
    fclose(log_file);
    exit(EXIT_FAILURE);
  }

  while (1) {
    memset(log_buffer, 0, MAX_BUF_LEN);

    ret = ioctl(fd, KL_CMD_GET_LOG, log_buffer);
    if (ret < 0) {
        fprintf(stderr, "ioctl KL_CMD_GET_LOG failed: %s\n", strerror(errno));
    } else if (ret > 0) {
        fprintf(log_file, "%s", log_buffer);
        fflush(log_file);
    }
    sleep(1);
  }

  close(fd);
  fclose(log_file);
  return 0;
}
