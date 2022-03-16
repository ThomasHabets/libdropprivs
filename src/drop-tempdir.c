/*
   Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#define _GNU_SOURCE
#include <grp.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mount.h>
#include <pwd.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <unistd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

int do_tempdir(gid_t gid)
{
  char jail[PATH_MAX];
  const char* tmpdir = getenv("TMPDIR");
  if (tmpdir == NULL) {
    tmpdir = "/tmp";
  }
  if (0 > snprintf(jail, PATH_MAX, "%s/jail-XXXXXX", tmpdir)) {
    perror("snprintf()");
    return 1;
  }
  if (mkdtemp(jail) == NULL) {
    perror("mkdtemp()");
    return 1;
  }
  // Ignore errors that only work as root.
  //
  // If cross-uid fail then setuid() will also fail, so it'll all even out in
  // the end.
  if (chown(jail, -1, gid) && errno != EPERM) {
    perror("chown(jail)");
    return 1;
  }
  if (chmod(jail, 0770) && errno != EPERM) {
    perror("chmod(jail)");
    return 1;
  }
  if (chdir(jail)) {
    perror("chdir(jail)");
    return 1;
  }
  // Caveat: Deleting the current working directory, and then chrooting into it,
  // may not be portable. If it's not, then skip the rmdir step and just leak
  // the directory..
  if (rmdir(jail)) {
    perror("rmdir()");
  }
  return 0;
}

int do_setuid(uid_t uid, gid_t gid)
{
  if (setgroups(0, NULL) && errno != EPERM) {
    perror("setgroups(0, NULL)");
  }
  if (setgid(gid) && errno != EPERM) {
    perror("setgid()");
  }
  if (setuid(uid) && errno != EPERM) {
    perror("setuid()");
  }
  return 0;
}

int drop_capabilities()
{
  cap_t no_cap;
  if (!(no_cap = cap_init())) {
    perror("cap_init()");
    return 1;
  }
  if (cap_set_proc(no_cap)) {
    perror("cap_set_proc()");
    return 1;
  }
  cap_free(no_cap);
}

int do_unshare()
{
  if (unshare(CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWUTS|CLONE_SYSVSEM))  {
    perror("unshare");
    return 1;
  }
  return 0;
}

int do_chroot()
{
  if (chroot(".")) {
    perror("chroot(.)");
    return 1;
  }
  return 0;
}

int drop_privs()
{
  struct passwd* pw = getpwnam("nobody");
  if (!pw) {
    perror("getpwnam(nobody)");
    return 1;
  }
  if (do_tempdir(pw->pw_gid)
      || do_setuid(pw->pw_uid, pw->pw_gid)
      || drop_capabilities()
      || do_unshare()
      || do_chroot()
      || drop_capabilities()) {
    return 1;
  }
  return 0;
}

int run_tests()
{
  printf("Tests:\n");
  printf("… Creating file should fail: %s\n",
         (fopen("/blah", "w") && errno == ENOENT) ? "FAIL" : "OK");

  printf("… Sending UDP packet should fail: ");
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == -1) {
    perror("socket()");
    return EXIT_FAILURE;
  }
  struct sockaddr_in sa;
  sa.sin_family = AF_INET;
  sa.sin_port = 12345;
  sa.sin_addr.s_addr = inet_addr("127.0.0.1");
  const char* data = "hello";
  const ssize_t rc = sendto(sock, data, strlen(data), 0, (struct sockaddr*)&sa,
                              sizeof(struct sockaddr_in));
  if (rc != -1) {
    printf("FAIL (sending succeeded\n");
    return EXIT_FAILURE;
  }
  if (errno != ENETUNREACH) {
    printf("FAIL (wrong error %s\n", strerror(errno));
    return EXIT_FAILURE;
  }
  printf("OK\n");
  return EXIT_SUCCESS;
}

int main()
{
  if (drop_privs()) {
    return EXIT_FAILURE;
  }
  int rc = run_tests();
  sleep(1800); // To allow inspecting /prod/<pid> stuff.
  return rc;
}
